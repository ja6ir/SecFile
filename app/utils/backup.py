import os
import shutil

def create_backup(file_path):
    backup_path = os.path.join('app/backups', os.path.basename(file_path))
    shutil.copy(file_path, backup_path)
    return backup_path

def recover_backup(backup_path, destination_path):
    shutil.copy(backup_path, destination_path)
