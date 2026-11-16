import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.privileges import elevate_to_admin, enable_all_privileges
from ui.app_window import SystemPurgeApp

def main():
    elevate_to_admin()
    enable_all_privileges()
    app = SystemPurgeApp()
    app.mainloop()

if __name__ == "__main__":
    main()
