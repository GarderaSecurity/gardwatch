import httpx
import tempfile
import tarfile
import zipfile
import shutil
import os
from pathlib import Path
from contextlib import asynccontextmanager

class PackageDownloader:
    def __init__(self, client: httpx.AsyncClient):
        self.client = client

    @asynccontextmanager
    async def download_and_extract(self, url: str):
        """
        Downloads a package archive and extracts it to a temporary directory.
        Yields the path to the extracted directory.
        """
        temp_dir = tempfile.mkdtemp(prefix="depsentry_")
        archive_path = Path(temp_dir) / "package.archive"
        
        try:
            # Download
            async with self.client.stream("GET", url, follow_redirects=True) as response:
                response.raise_for_status()
                with open(archive_path, "wb") as f:
                    async for chunk in response.aiter_bytes():
                        f.write(chunk)
            
            # Extract
            extract_dir = Path(temp_dir) / "extracted"
            extract_dir.mkdir()
            
            if tarfile.is_tarfile(archive_path):
                with tarfile.open(archive_path, "r:*") as tar:
                    # filtering='data' is safer but requires Python 3.12+
                    # We are on 3.12, so we can use it to prevent traversal attacks
                    tar.extractall(extract_dir, filter='data')
            elif zipfile.is_zipfile(archive_path):
                with zipfile.ZipFile(archive_path, "r") as zip_ref:
                    zip_ref.extractall(extract_dir)
            
            yield extract_dir
            
        except Exception as e:
            # Re-raise or handle logging
            raise e
        finally:
            # Cleanup
            shutil.rmtree(temp_dir, ignore_errors=True)
