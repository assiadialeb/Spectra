class BaseParser:
    def parse(self, data, scan_id, base_path=None):
        raise NotImplementedError
    
    def normalize_path(self, path, base_path):
        if not path or not base_path:
            return path
        # Remove base_path and possible leading slashes
        if path.startswith(base_path):
            return path[len(base_path):].lstrip('/')
        return path
