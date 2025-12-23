import os
from typing import List, Dict, Optional
from pathlib import Path
import json
import csv
from ..utils.logger import get_logger, log_errors, PerformanceLogger

class IOCReader:
    """Reads IOCs from various input sources."""
    
    def __init__(self):
        self.supported_formats = ['txt', 'json', 'csv']
        self.logger = get_logger()
    
    @log_errors()
    def read_from_file(self, file_path: str) -> List[str]:
        """
        Read IOCs from a file.
        
        Args:
            file_path: Path to the file containing IOCs
            
        Returns:
            List of IOC strings
            
        Raises:
            FileNotFoundError: If file doesn't exist
            ValueError: If file format is not supported
            PermissionError: If file cannot be read
        """
        with PerformanceLogger("read_from_file", self.logger):
            file_path = Path(file_path)
            
            # Validate file exists and is readable
            if not file_path.exists():
                raise FileNotFoundError(f"File not found: {file_path}")
            
            if not file_path.is_file():
                raise ValueError(f"Path is not a file: {file_path}")
            
            if not os.access(file_path, os.R_OK):
                raise PermissionError(f"File not readable: {file_path}")
            
            # Get file extension
            file_ext = file_path.suffix.lower().lstrip('.')
            
            if file_ext not in self.supported_formats:
                raise ValueError(f"Unsupported file format: {file_ext}. Supported formats: {self.supported_formats}")
            
            self.logger.info(f"Reading IOCs from file: {file_path} (format: {file_ext})")
            
            try:
                if file_ext == 'txt':
                    return self._read_txt_file(file_path)
                elif file_ext == 'json':
                    return self._read_json_file(file_path)
                elif file_ext == 'csv':
                    return self._read_csv_file(file_path)
            except Exception as e:
                self.logger.error(f"Error reading file {file_path}: {str(e)}")
                raise
    
    def _read_txt_file(self, file_path: Path) -> List[str]:
        """Read IOCs from a text file."""
        iocs = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if line and not line.startswith('#'):  # Skip empty lines and comments
                        iocs.append(line)
            
            self.logger.info(f"Read {len(iocs)} IOCs from text file")
            return iocs
        except UnicodeDecodeError as e:
            self.logger.error(f"Encoding error in file {file_path}: {str(e)}")
            raise ValueError(f"File encoding error: {str(e)}")
    
    def _read_json_file(self, file_path: Path) -> List[str]:
        """Read IOCs from a JSON file."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            iocs = []
            
            # Handle different JSON structures
            if isinstance(data, list):
                # List of IOCs or list of IOC objects
                for item in data:
                    if isinstance(item, str):
                        iocs.append(item)
                    elif isinstance(item, dict) and 'ioc' in item:
                        iocs.append(item['ioc'])
                    elif isinstance(item, dict) and 'ioc_value' in item:
                        iocs.append(item['ioc_value'])
            elif isinstance(data, dict):
                # Single IOC object or dict with IOC list
                if 'ioc' in data:
                    iocs.append(data['ioc'])
                elif 'ioc_value' in data:
                    iocs.append(data['ioc_value'])
                elif 'iocs' in data:
                    iocs.extend(data['iocs'])
                elif 'indicators' in data:
                    iocs.extend(data['indicators'])
            
            self.logger.info(f"Read {len(iocs)} IOCs from JSON file")
            return iocs
        except json.JSONDecodeError as e:
            self.logger.error(f"Invalid JSON in file {file_path}: {str(e)}")
            raise ValueError(f"Invalid JSON format: {str(e)}")
    
    def _read_csv_file(self, file_path: Path) -> List[str]:
        """Read IOCs from a CSV file."""
        iocs = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                # Detect CSV dialect
                sample = f.read(1024)
                f.seek(0)
                sniffer = csv.Sniffer()
                
                try:
                    dialect = sniffer.sniff(sample)
                except csv.Error:
                    dialect = csv.excel  # Default to Excel dialect
                
                reader = csv.DictReader(f, dialect=dialect)
                
                # Try to find IOC column
                ioc_column = None
                possible_columns = ['ioc', 'ioc_value', 'indicator', 'value', 'domain', 'ip', 'url', 'hash']
                
                if reader.fieldnames:
                    for col in possible_columns:
                        if col.lower() in [field.lower() for field in reader.fieldnames]:
                            ioc_column = col
                            break
                
                if not ioc_column:
                    # If no obvious IOC column, use the first column
                    if reader.fieldnames:
                        ioc_column = reader.fieldnames[0]
                        self.logger.warning(f"No obvious IOC column found, using first column: {ioc_column}")
                    else:
                        raise ValueError("CSV file has no headers or columns")
                
                for row_num, row in enumerate(reader, 2):  # Start at 2 to account for header
                    if ioc_column and ioc_column in row:
                        ioc_value = row[ioc_column].strip()
                        if ioc_value:
                            iocs.append(ioc_value)
            
            self.logger.info(f"Read {len(iocs)} IOCs from CSV file using column: {ioc_column}")
            return iocs
        except Exception as e:
            self.logger.error(f"Error reading CSV file {file_path}: {str(e)}")
            raise ValueError(f"CSV reading error: {str(e)}")
    
    @log_errors()
    def read_from_text(self, text_input: str) -> List[str]:
        """
        Read IOCs from text input.
        
        Args:
            text_input: Text containing IOCs
            
        Returns:
            List of IOC strings
        """
        with PerformanceLogger("read_from_text", self.logger):
            if not text_input or not isinstance(text_input, str):
                raise ValueError("Invalid text input")
            
            # Split by common delimiters
            lines = text_input.replace(',', '\n').replace(';', '\n').split('\n')
            
            iocs = []
            for line in lines:
                line = line.strip()
                if line and not line.startswith('#'):  # Skip empty lines and comments
                    iocs.append(line)
            
            self.logger.info(f"Parsed {len(iocs)} IOCs from text input")
            return iocs
    
    def _read_txt_file(self, file_path: Path) -> List[str]:
        """Read IOCs from a text file (one per line)."""
        iocs = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):  # Skip comments and empty lines
                        iocs.append(line)
        except UnicodeDecodeError:
            # Try with different encoding
            with open(file_path, 'r', encoding='latin-1') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        iocs.append(line)
        
        return iocs
    
    def _read_json_file(self, file_path: Path) -> List[str]:
        """Read IOCs from a JSON file."""
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        iocs = []
        
        # Handle different JSON structures
        if isinstance(data, list):
            for item in data:
                if isinstance(item, str):
                    iocs.append(item)
                elif isinstance(item, dict):
                    # Look for common IOC field names
                    for field in ['ioc', 'indicator', 'value', 'indicator_value']:
                        if field in item and isinstance(item[field], str):
                            iocs.append(item[field])
                            break
        elif isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, str):
                    iocs.append(value)
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, str):
                            iocs.append(item)
        
        return iocs
    
    def _read_csv_file(self, file_path: Path) -> List[str]:
        """Read IOCs from a CSV file."""
        iocs = []
        
        with open(file_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            
            # Look for common IOC column names
            ioc_columns = ['ioc', 'indicator', 'value', 'indicator_value', 'threat', 'url', 'ip', 'domain', 'hash']
            
            for row in reader:
                for col in ioc_columns:
                    if col in row and row[col].strip():
                        iocs.append(row[col].strip())
                        break  # Take the first matching column per row
        
        return iocs
    
    def read_from_stdin(self) -> List[str]:
        """Read IOCs from standard input."""
        import sys
        
        iocs = []
        print("Enter IOCs (one per line). Press Ctrl+D or Ctrl+Z to finish:")
        
        try:
            for line in sys.stdin:
                line = line.strip()
                if line and not line.startswith('#'):
                    iocs.append(line)
        except KeyboardInterrupt:
            pass
        
        return iocs
    
    def read_from_string(self, ioc_string: str) -> List[str]:
        """
        Read IOCs from a string (comma, space, or newline separated).
        
        Args:
            ioc_string: String containing IOCs
            
        Returns:
            List of IOC strings
        """
        # Split by common delimiters
        iocs = []
        
        # Try comma-separated first
        if ',' in ioc_string:
            iocs = [ioc.strip() for ioc in ioc_string.split(',') if ioc.strip()]
        # Try space-separated
        elif ' ' in ioc_string:
            iocs = [ioc.strip() for ioc in ioc_string.split() if ioc.strip()]
        # Try newline-separated
        elif '\n' in ioc_string:
            iocs = [ioc.strip() for ioc in ioc_string.split('\n') if ioc.strip()]
        else:
            # Single IOC
            iocs = [ioc_string.strip()] if ioc_string.strip() else []
        
        return iocs
    
    def read_batch_files(self, file_paths: List[str]) -> Dict[str, List[str]]:
        """
        Read IOCs from multiple files.
        
        Args:
            file_paths: List of file paths
            
        Returns:
            Dictionary with file paths as keys and IOC lists as values
        """
        results = {}
        
        for file_path in file_paths:
            try:
                iocs = self.read_from_file(file_path)
                results[file_path] = iocs
            except Exception as e:
                results[file_path] = f"Error: {str(e)}"
        
        return results
    
    def validate_file_format(self, file_path: str) -> bool:
        """
        Check if file format is supported.
        
        Args:
            file_path: Path to the file
            
        Returns:
            True if format is supported, False otherwise
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            return False
        
        file_ext = file_path.suffix.lower().lstrip('.')
        return file_ext in self.supported_formats
