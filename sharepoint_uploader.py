"""
Mission Control — SharePoint Upload Module
Uploads PDF audit reports to client SharePoint sites via Microsoft Graph API.
Uses MSAL client credentials flow (Azure AD app registration per tenant).
"""
import logging
import os
import requests
from typing import Optional, Tuple

logger = logging.getLogger("sharepoint_uploader")

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
GRAPH_SCOPE = ["https://graph.microsoft.com/.default"]

# Max file size for simple upload (4 MB). Larger files need upload session.
SIMPLE_UPLOAD_LIMIT = 4 * 1024 * 1024


def get_graph_token(tenant_id: str, client_id: str, client_secret: str) -> str:
    """Acquire an access token using OAuth2 client credentials flow via MSAL."""
    import msal

    authority = f"https://login.microsoftonline.com/{tenant_id}"
    app = msal.ConfidentialClientApplication(
        client_id,
        authority=authority,
        client_credential=client_secret,
    )
    result = app.acquire_token_for_client(scopes=GRAPH_SCOPE)

    if "access_token" not in result:
        error = result.get("error_description") or result.get("error") or "Unknown auth error"
        raise RuntimeError(f"SharePoint auth failed: {error}")

    return result["access_token"]


def _headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}", "Accept": "application/json"}


def resolve_site_id(token: str, sharepoint_site_url: str) -> str:
    """
    Resolve a SharePoint site URL to a Graph site ID.
    Accepts formats like:
      contoso.sharepoint.com:/sites/MySite
      contoso.sharepoint.com,site-guid,web-guid
      https://contoso.sharepoint.com/sites/MySite
    """
    url = sharepoint_site_url.strip()

    # Strip protocol
    for prefix in ("https://", "http://"):
        if url.lower().startswith(prefix):
            url = url[len(prefix):]

    # If already in hostname:/path format, use directly
    if ":/" in url:
        hostname, path = url.split(":/", 1)
        path = "/" + path.strip("/")
        endpoint = f"{GRAPH_BASE}/sites/{hostname}:{path}"
    elif "/" in url:
        # contoso.sharepoint.com/sites/MySite -> hostname:/sites/MySite
        parts = url.split("/", 1)
        hostname = parts[0]
        path = "/" + parts[1].strip("/")
        endpoint = f"{GRAPH_BASE}/sites/{hostname}:{path}"
    else:
        # Just a hostname — root site
        endpoint = f"{GRAPH_BASE}/sites/{url}"

    resp = requests.get(endpoint, headers=_headers(token), timeout=30)
    resp.raise_for_status()
    data = resp.json()
    site_id = data.get("id")
    if not site_id:
        raise RuntimeError(f"Could not resolve site ID from {sharepoint_site_url}")
    return site_id


def resolve_drive_id(token: str, sharepoint_site_url: str, drive_name: Optional[str] = None) -> Tuple[str, str]:
    """
    Resolve the default document library drive ID for a SharePoint site.
    Returns (site_id, drive_id).
    If drive_name is provided, looks for a matching drive; otherwise uses the default.
    """
    site_id = resolve_site_id(token, sharepoint_site_url)

    if drive_name:
        endpoint = f"{GRAPH_BASE}/sites/{site_id}/drives"
        resp = requests.get(endpoint, headers=_headers(token), timeout=30)
        resp.raise_for_status()
        drives = resp.json().get("value", [])
        for drive in drives:
            if drive.get("name", "").lower() == drive_name.lower():
                return site_id, drive["id"]
        available = [d.get("name") for d in drives]
        raise RuntimeError(f"Drive '{drive_name}' not found. Available: {available}")

    # Default document library
    endpoint = f"{GRAPH_BASE}/sites/{site_id}/drive"
    resp = requests.get(endpoint, headers=_headers(token), timeout=30)
    resp.raise_for_status()
    drive_id = resp.json().get("id")
    if not drive_id:
        raise RuntimeError("Could not resolve default drive")
    return site_id, drive_id


def ensure_folder(token: str, drive_id: str, folder_path: str) -> str:
    """Ensure the target folder exists, creating it if needed. Returns the folder item ID."""
    folder_path = folder_path.strip("/")
    if not folder_path:
        return "root"

    # Try to get the folder first
    endpoint = f"{GRAPH_BASE}/drives/{drive_id}/root:/{folder_path}"
    resp = requests.get(endpoint, headers=_headers(token), timeout=30)
    if resp.status_code == 200:
        return resp.json()["id"]

    # Create folder path segment by segment
    parts = folder_path.split("/")
    parent_id = "root"

    for part in parts:
        check_url = f"{GRAPH_BASE}/drives/{drive_id}/items/{parent_id}/children"
        resp = requests.get(
            check_url, headers=_headers(token), timeout=30,
            params={"$filter": f"name eq '{part}'"},
        )
        items = resp.json().get("value", []) if resp.status_code == 200 else []

        existing = next((i for i in items if i.get("name") == part), None)
        if existing:
            parent_id = existing["id"]
        else:
            create_url = f"{GRAPH_BASE}/drives/{drive_id}/items/{parent_id}/children"
            body = {
                "name": part,
                "folder": {},
                "@microsoft.graph.conflictBehavior": "fail",
            }
            resp = requests.post(create_url, headers=_headers(token), json=body, timeout=30)
            if resp.status_code == 409:
                # Already exists (race condition), re-fetch
                resp2 = requests.get(
                    check_url, headers=_headers(token), timeout=30,
                    params={"$filter": f"name eq '{part}'"},
                )
                items2 = resp2.json().get("value", []) if resp2.status_code == 200 else []
                existing2 = next((i for i in items2 if i.get("name") == part), None)
                if existing2:
                    parent_id = existing2["id"]
                else:
                    raise RuntimeError(f"Could not create or find folder segment: {part}")
            else:
                resp.raise_for_status()
                parent_id = resp.json()["id"]

    return parent_id


def upload_file(token: str, drive_id: str, folder_path: str, local_file_path: str, filename: str) -> dict:
    """
    Upload a file to SharePoint via Graph API.
    Uses simple upload for files under 4 MB, upload session for larger files.
    Returns the Graph API item metadata including webUrl.
    """
    file_size = os.path.getsize(local_file_path)
    folder_path = folder_path.strip("/")

    if folder_path:
        upload_path = f"{folder_path}/{filename}"
    else:
        upload_path = filename

    if file_size <= SIMPLE_UPLOAD_LIMIT:
        endpoint = f"{GRAPH_BASE}/drives/{drive_id}/root:/{upload_path}:/content"
        with open(local_file_path, "rb") as f:
            data = f.read()

        headers = _headers(token)
        headers["Content-Type"] = "application/pdf"
        resp = requests.put(endpoint, headers=headers, data=data, timeout=120)
        resp.raise_for_status()
        return resp.json()

    else:
        # Large file — use upload session
        endpoint = f"{GRAPH_BASE}/drives/{drive_id}/root:/{upload_path}:/createUploadSession"
        body = {
            "item": {
                "@microsoft.graph.conflictBehavior": "replace",
                "name": filename,
            },
        }
        resp = requests.post(endpoint, headers=_headers(token), json=body, timeout=30)
        resp.raise_for_status()
        upload_url = resp.json()["uploadUrl"]

        chunk_size = 10 * 1024 * 1024  # 10 MB chunks
        with open(local_file_path, "rb") as f:
            offset = 0
            while offset < file_size:
                chunk = f.read(chunk_size)
                chunk_len = len(chunk)
                end = offset + chunk_len - 1
                headers = {
                    "Content-Length": str(chunk_len),
                    "Content-Range": f"bytes {offset}-{end}/{file_size}",
                }
                resp = requests.put(upload_url, headers=headers, data=chunk, timeout=120)
                resp.raise_for_status()
                offset += chunk_len

            return resp.json()


def upload_report_to_sharepoint(site_config: dict, local_pdf_path: str, filename: str) -> dict:
    """
    Full orchestration: authenticate, resolve drive, ensure folder, upload file.
    Returns dict with sharepoint_url, drive_id, item_id.
    """
    tenant_id = site_config.get("sharepoint_tenant_id")
    client_id = site_config.get("sharepoint_client_id")
    client_secret = site_config.get("sharepoint_client_secret")
    site_url = site_config.get("sharepoint_site_url")
    drive_id = site_config.get("sharepoint_drive_id")
    folder = site_config.get("sharepoint_folder") or ""

    if not all([tenant_id, client_id, client_secret, site_url]):
        raise RuntimeError(
            "Incomplete SharePoint configuration — "
            "tenant_id, client_id, client_secret, and site_url are all required"
        )

    token = get_graph_token(tenant_id, client_id, client_secret)

    if not drive_id:
        _, drive_id = resolve_drive_id(token, site_url)

    ensure_folder(token, drive_id, folder)
    item = upload_file(token, drive_id, folder, local_pdf_path, filename)

    return {
        "sharepoint_url": item.get("webUrl"),
        "drive_id": drive_id,
        "item_id": item.get("id"),
        "filename": filename,
        "size": item.get("size"),
    }


def test_sharepoint_connection(site_config: dict) -> dict:
    """
    Validate SharePoint credentials and folder access without uploading.
    Returns status dict.
    """
    tenant_id = site_config.get("sharepoint_tenant_id")
    client_id = site_config.get("sharepoint_client_id")
    client_secret = site_config.get("sharepoint_client_secret")
    site_url = site_config.get("sharepoint_site_url")
    drive_id_cfg = site_config.get("sharepoint_drive_id")
    folder = site_config.get("sharepoint_folder") or ""

    result = {
        "auth": False,
        "site_resolved": False,
        "drive_resolved": False,
        "folder_accessible": False,
        "drive_id": None,
        "site_display_name": None,
        "error": None,
    }

    if not all([tenant_id, client_id, client_secret, site_url]):
        result["error"] = "Incomplete config — tenant_id, client_id, client_secret, site_url required"
        return result

    try:
        token = get_graph_token(tenant_id, client_id, client_secret)
        result["auth"] = True
    except Exception as e:
        result["error"] = f"Auth failed: {e}"
        return result

    try:
        graph_site_id = resolve_site_id(token, site_url)
        result["site_resolved"] = True

        # Get display name
        resp = requests.get(
            f"{GRAPH_BASE}/sites/{graph_site_id}",
            headers=_headers(token), timeout=30,
        )
        if resp.ok:
            result["site_display_name"] = resp.json().get("displayName")
    except Exception as e:
        result["error"] = f"Site resolution failed: {e}"
        return result

    try:
        if drive_id_cfg:
            resp = requests.get(
                f"{GRAPH_BASE}/drives/{drive_id_cfg}",
                headers=_headers(token), timeout=30,
            )
            resp.raise_for_status()
            result["drive_id"] = drive_id_cfg
        else:
            _, discovered_drive_id = resolve_drive_id(token, site_url)
            result["drive_id"] = discovered_drive_id
        result["drive_resolved"] = True
    except Exception as e:
        result["error"] = f"Drive resolution failed: {e}"
        return result

    try:
        if folder:
            ensure_folder(token, result["drive_id"], folder)
        result["folder_accessible"] = True
    except Exception as e:
        result["error"] = f"Folder access failed: {e}"
        return result

    return result
