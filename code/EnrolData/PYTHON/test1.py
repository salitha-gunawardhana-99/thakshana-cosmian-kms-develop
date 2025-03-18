import paramiko

def run_ssh_command(host, port, user, password, command):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, port=port, username=user, password=password)
    
    stdin, stdout, stderr = client.exec_command(command)
    output = stdout.read().decode()
    error = stderr.read().decode()
    client.close()
    return output, error

# Usage
host = "localhost"
port = 2222
user = "root"
password = "pass123"
docker_command = "ckms sym keys createx"
output, error = run_ssh_command(host, port, user, password, docker_command)
print("Command Output:", output)
print("Command Error:", error)
