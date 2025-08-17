import os
import zipfile
import datetime

"""
Simple backup script for the skaner4 project.
Creates a ZIP archive of the project folder with a timestamp.
"""

def create_backup():
    # Determine project root (directory containing this script)
    project_root = os.path.abspath(os.path.dirname(__file__))
    # Create backups directory
    backup_dir = os.path.join(project_root, 'backups')
    os.makedirs(backup_dir, exist_ok=True)

    # Prepare backup file name with timestamp
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_name = f'skaner4_backup_{timestamp}.zip'
    backup_path = os.path.join(backup_dir, backup_name)

    # Create zip archive
    with zipfile.ZipFile(backup_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(project_root):
            # Skip backups directory itself
            if os.path.abspath(root).startswith(os.path.abspath(backup_dir)):
                continue
            for file in files:
                file_path = os.path.join(root, file)
                # Skip this backup script
                if file_path == os.path.abspath(__file__):
                    continue
                # Compute archive name by stripping project_root prefix
                arcname = os.path.relpath(file_path, project_root)
                zipf.write(file_path, arcname)
    print(f'Backup created: {backup_path}')


if __name__ == '__main__':
    create_backup()
