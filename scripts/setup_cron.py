#!/usr/bin/env python3
"""
PulseLens Cron Job Setup Script
Sets up automated analysis cron jobs
"""

import os
import sys
from pathlib import Path
import argparse
import json
from datetime import datetime
from typing import Dict, List

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from pulselens.utils.logger import get_logger


class CronSetup:
    """Handles cron job setup for automated analysis."""
    
    def __init__(self):
        """Initialize cron setup."""
        self.logger = get_logger()
        self.script_path = project_root / "scripts" / "automated_analysis.py"
        self.cron_file = Path.home() / ".pulselens_cron"
        self.log_dir = project_root / "logs"
        self.log_dir.mkdir(exist_ok=True)
    
    def setup_daily_analysis(self, input_dir: str, output_dir: str = "reports", 
                           time: str = "02:00") -> str:
        """
        Setup daily automated analysis.
        
        Args:
            input_dir: Directory containing IOC files
            output_dir: Directory for reports
            time: Time in HH:MM format (24-hour)
            
        Returns:
            Cron entry
        """
        hour, minute = time.split(':')
        
        # Create log file path
        log_file = self.log_dir / "daily_analysis.log"
        
        cron_entry = f"{minute} {hour} * * * cd {project_root} && python {self.script_path} --mode directory --input {input_dir} --output {output_dir} >> {log_file} 2>&1"
        
        self.logger.info(f"Daily analysis cron entry: {cron_entry}")
        return cron_entry
    
    def setup_recent_feeds_analysis(self, hours: int = 24, output_dir: str = "reports",
                                   interval: str = "hourly") -> str:
        """
        Setup recent feeds analysis.
        
        Args:
            hours: Hours to look back
            output_dir: Directory for reports
            interval: Schedule interval (hourly, daily, weekly)
            
        Returns:
            Cron entry
        """
        # Create log file path
        log_file = self.log_dir / "recent_feeds.log"
        
        if interval == "hourly":
            cron_entry = f"0 * * * * cd {project_root} && python {self.script_path} --mode recent --hours {hours} --output {output_dir} >> {log_file} 2>&1"
        elif interval == "daily":
            cron_entry = f"0 3 * * * cd {project_root} && python {self.script_path} --mode recent --hours {hours} --output {output_dir} >> {log_file} 2>&1"
        elif interval == "weekly":
            cron_entry = f"0 4 * * 0 cd {project_root} && python {self.script_path} --mode recent --hours {hours} --output {output_dir} >> {log_file} 2>&1"
        else:
            raise ValueError(f"Unsupported interval: {interval}")
        
        self.logger.info(f"Recent feeds analysis cron entry: {cron_entry}")
        return cron_entry
    
    def setup_weekly_report(self, input_dir: str, output_dir: str = "reports",
                          day: str = "sunday", time: str = "01:00") -> str:
        """
        Setup weekly comprehensive analysis.
        
        Args:
            input_dir: Directory containing IOC files
            output_dir: Directory for reports
            day: Day of week (monday, tuesday, etc.)
            time: Time in HH:MM format
            
        Returns:
            Cron entry
        """
        # Convert day to cron format (0=Sunday, 1=Monday, etc.)
        day_map = {
            'sunday': 0, 'monday': 1, 'tuesday': 2, 'wednesday': 3,
            'thursday': 4, 'friday': 5, 'saturday': 6
        }
        
        if day.lower() not in day_map:
            raise ValueError(f"Invalid day: {day}")
        
        day_num = day_map[day.lower()]
        hour, minute = time.split(':')
        
        # Create log file path
        log_file = self.log_dir / "weekly_analysis.log"
        
        cron_entry = f"{minute} {hour} * * {day_num} cd {project_root} && python {self.script_path} --mode directory --input {input_dir} --output {output_dir} >> {log_file} 2>&1"
        
        self.logger.info(f"Weekly analysis cron entry: {cron_entry}")
        return cron_entry
    
    def install_cron_jobs(self, cron_entries: List[str], dry_run: bool = False) -> bool:
        """
        Install cron jobs.
        
        Args:
            cron_entries: List of cron entries
            dry_run: If True, only show what would be installed
            
        Returns:
            Success status
        """
        try:
            # Read existing crontab
            import subprocess
            result = subprocess.run(['crontab', '-l'], capture_output=True, text=True)
            
            if result.returncode == 0:
                existing_cron = result.stdout
            else:
                existing_cron = ""
            
            # Add new entries
            new_cron = existing_cron
            
            # Remove existing PulseLens entries
            lines = existing_cron.split('\n')
            filtered_lines = [line for line in lines if 'pulselens' not in line.lower()]
            new_cron = '\n'.join(filtered_lines)
            
            # Add new entries
            if new_cron and not new_cron.endswith('\n'):
                new_cron += '\n'
            
            new_cron += "\n# PulseLens Automated Analysis Jobs\n"
            for entry in cron_entries:
                new_cron += entry + "\n"
            
            if dry_run:
                print("Dry run - would install the following cron entries:")
                print(new_cron)
                return True
            
            # Write new crontab
            process = subprocess.Popen(['crontab', '-'], stdin=subprocess.PIPE, text=True)
            process.communicate(input=new_cron)
            
            if process.returncode == 0:
                self.logger.info("Cron jobs installed successfully")
                return True
            else:
                self.logger.error("Failed to install cron jobs")
                return False
                
        except Exception as e:
            self.logger.error(f"Error installing cron jobs: {str(e)}")
            return False
    
    def create_systemd_service(self, service_name: str = "pulselens-analysis") -> str:
        """
        Create systemd service file for PulseLens analysis.
        
        Args:
            service_name: Name of the service
            
        Returns:
            Path to service file
        """
        service_content = f"""[Unit]
Description=PulseLens IOC Analysis Service
After=network.target

[Service]
Type=oneshot
User={os.getenv('USER', 'root')}
WorkingDirectory={project_root}
ExecStart=python {self.script_path} --mode recent --hours 24 --output reports
StandardOutput=append:{self.log_dir}/service.log
StandardError=append:{self.log_dir}/service_error.log

[Install]
WantedBy=multi-user.target
"""
        
        service_file = f"/etc/systemd/system/{service_name}.service"
        
        try:
            with open(f"{service_name}.service", 'w') as f:
                f.write(service_content)
            
            self.logger.info(f"Systemd service file created: {service_name}.service")
            return service_file
            
        except Exception as e:
            self.logger.error(f"Error creating systemd service: {str(e)}")
            raise
    
    def generate_setup_script(self, config: Dict) -> str:
        """
        Generate setup script for manual installation.
        
        Args:
            config: Configuration dictionary
            
        Returns:
            Setup script content
        """
        script_content = f"""#!/bin/bash
# PulseLens Automated Analysis Setup Script
# Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

echo "Setting up PulseLens automated analysis..."

# Create directories
mkdir -p {self.log_dir}
mkdir -p {config.get('output_dir', 'reports')}

# Install cron jobs
echo "Installing cron jobs..."

"""
        
        # Add cron entries based on config
        if config.get('daily_analysis'):
            daily_entry = self.setup_daily_analysis(
                config['daily_analysis']['input_dir'],
                config['daily_analysis'].get('output_dir', 'reports'),
                config['daily_analysis'].get('time', '02:00')
            )
            script_content += f'echo "{daily_entry}" | crontab -\n'
        
        if config.get('recent_feeds'):
            recent_entry = self.setup_recent_feeds_analysis(
                config['recent_feeds'].get('hours', 24),
                config['recent_feeds'].get('output_dir', 'reports'),
                config['recent_feeds'].get('interval', 'hourly')
            )
            script_content += f'echo "{recent_entry}" | crontab -\n'
        
        script_content += """
echo "Cron jobs installed successfully!"
echo "Check with: crontab -l"
echo "Logs will be stored in: {log_dir}"
"""
        
        return script_content


def main():
    """Main entry point for cron setup."""
    parser = argparse.ArgumentParser(description='PulseLens Cron Job Setup')
    parser.add_argument('--mode', choices=['daily', 'recent', 'weekly', 'systemd'], required=True,
                       help='Setup mode')
    parser.add_argument('--input-dir', help='Input directory for IOC files')
    parser.add_argument('--output-dir', default='reports', help='Output directory')
    parser.add_argument('--time', help='Time in HH:MM format')
    parser.add_argument('--day', default='sunday', help='Day of week for weekly jobs')
    parser.add_argument('--hours', type=int, default=24, help='Hours for recent feeds')
    parser.add_argument('--interval', choices=['hourly', 'daily', 'weekly'], default='hourly',
                       help='Interval for recent feeds')
    parser.add_argument('--dry-run', action='store_true', help='Show what would be installed')
    parser.add_argument('--install', action='store_true', help='Install cron jobs')
    
    args = parser.parse_args()
    
    try:
        setup = CronSetup()
        cron_entries = []
        
        if args.mode == 'daily':
            if not args.input_dir:
                print("Error: --input-dir required for daily mode")
                sys.exit(1)
            
            entry = setup.setup_daily_analysis(args.input_dir, args.output_dir, args.time or "02:00")
            cron_entries.append(entry)
            
        elif args.mode == 'recent':
            entry = setup.setup_recent_feeds_analysis(args.hours, args.output_dir, args.interval)
            cron_entries.append(entry)
            
        elif args.mode == 'weekly':
            if not args.input_dir:
                print("Error: --input-dir required for weekly mode")
                sys.exit(1)
            
            entry = setup.setup_weekly_report(args.input_dir, args.output_dir, args.day, args.time or "01:00")
            cron_entries.append(entry)
            
        elif args.mode == 'systemd':
            service_file = setup.create_systemd_service()
            print(f"Systemd service file created: {service_file}")
            print("To enable: sudo systemctl enable pulselens-analysis")
            print("To start: sudo systemctl start pulselens-analysis")
            return
        
        if args.install:
            success = setup.install_cron_jobs(cron_entries, args.dry_run)
            if success:
                print("Cron jobs installed successfully!")
            else:
                print("Failed to install cron jobs")
                sys.exit(1)
        else:
            print("Cron entries to install:")
            for entry in cron_entries:
                print(f"  {entry}")
            print("\nUse --install to actually install these cron jobs")
            
    except Exception as e:
        print(f"Setup failed: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
