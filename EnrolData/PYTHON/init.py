import subprocess
from typing import Optional, Tuple
import time
import pexpect
import paramiko
import getpass


# Function to run a shell command and return a tuple (success, message)
def run_command(command: str) -> Tuple[bool, str]:
    try:
        # Run the command and capture the output
        result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
        return (True, result.decode("utf-8").strip())
    except subprocess.CalledProcessError as e:
        # Return False and the error message if the command fails
        return (False, e.output.decode("utf-8").strip())
    
    
def check_and_install_docker():
    # Check if Docker is installed by running 'docker --version'
    if run_command("docker --version")[0]==True:
        print("Docker is already installed.")
    else:
        print("Docker is not installed. Installing Docker.")

        # Uninstall conflicting packages
        print("Removing any conflicting packages.")
        conflicting_packages = ["docker.io", "docker-doc", "docker-compose", "docker-compose-v2", "podman-docker", "containerd", "runc"]
        for pkg in conflicting_packages:
            run_command(f"sudo apt-get remove -y {pkg}")
        
        # Update package list
        run_command("sudo apt-get update")
        
        # Install necessary packages
        run_command("sudo apt-get install -y ca-certificates curl")

        # Create the keyrings directory for Docker's GPG key
        run_command("sudo install -m 0755 -d /etc/apt/keyrings")
        
        # Add Docker's official GPG key
        run_command("sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc")
        run_command("sudo chmod a+r /etc/apt/keyrings/docker.asc")

        # Add Docker's repository to Apt sources
        run_command('echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null')
        
        # Update package list again after adding Docker's repository
        run_command("sudo apt-get update")
        
        # Install Docker packages
        print("Installing Docker packages.")
        run_command("sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin")

        # Check if Docker installed successfully
        if run_command("docker --version")[0]:
            print("Docker installed successfully.")
        else:
            print("Failed to install Docker. Please check your network connection or try installing manually.")


def check_and_install_kms():
    # Check if the 'kms' container exists and has the correct port mapping
    container_info = run_command("docker ps -a --filter 'name=kms' --format '{{.Names}}:{{.Ports}}'")
    
    if container_info[0] and "kms" in container_info[1] and "2222->22/tcp" in container_info[1]:
        print("Container 'kms' with port mapping 2222:22 is already available.")
    else:
        print("Condition not met. Proceeding with setup.")

        # Check if the container named 'kms' exists (running or stopped)
        existing_container = run_command("docker ps -a --filter 'name=kms' --format '{{.Names}}'")
        if existing_container[0]:
            print("Removing existing 'kms' container.")
            run_command("docker rm -f kms")
        
        # Install the 'kms' container with the specified port mapping
        print("Installing 'kms' container with port mapping 2222:22.")
        run_command("docker run -d -p 2222:22 --name kms ghcr.io/cosmian/kms:4.19.1")


def setup_kms_container_ssh():
    # Check if 'kms' container is running
    container_status = run_command("docker inspect -f '{{.State.Running}}' kms")
    if container_status[1] != "true":
        print("Starting 'kms' container.")
        run_command("docker start kms")

    # Check if SSH server (sshd) is available in the container
    ssh_check_command = "docker exec kms which sshd"
    sshd_path = run_command(ssh_check_command)
    
    if not sshd_path[0]:
        print("Installing SSH server in 'kms' container.")
        # Update package list and install OpenSSH server
        run_command("docker exec kms apt update")
        run_command("docker exec kms apt install -y openssh-server")

    # Install nano if needed for editing configuration file
    # print("Installing nano in 'kms' container.")
    # run_command("docker exec kms apt install -y nano")

    # Modify SSH configuration to permit root login
    print("Modifying SSH configuration to permit root login.")
    run_command("docker exec kms sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config")
    
    # Set root password
    print("Setting root password.")
    run_command("docker exec kms bash -c 'echo \"root:pass123\" | chpasswd'")

    # Start SSH service
    print("Starting SSH service in 'kms' container.")
    run_command("docker exec kms service ssh start")

    print("SSH setup completed for 'kms' container.")


# SSH installation failed. check it
def check_and_install_client_side_ssh():
    # Attempt to check if SSH client is installed
    result = run_command("ssh -V")
    if result[0]:
        print("SSH client is already installed.")
    else:
        print("SSH client not found. Installing.")

        # Update package list and install SSH client
        update_result = run_command("sudo apt update")
        if update_result[0]:
            install_result = run_command("sudo apt install -y openssh-client")
            if install_result[0]:
                print("SSH client installed successfully.")
            else:
                print("Failed to install SSH client.")
        else:
            print("Failed to update package list. Please resolve the issues and try again.")


def setup_client_side_ssh():
    # Step 1: Check if 'kms' container is running; if not, start it
    container_status = run_command("docker inspect -f '{{.State.Running}}' kms")
    if container_status[1] != "true":
        print("Starting 'kms' container...")
        run_command("docker start kms")
        time.sleep(3)  # Wait a moment for the container to initialize

    # Step 2: Try to establish SSH connection
    ssh_command = "ssh root@localhost -p 2222"
    result = run_command(ssh_command)

    if not result[0]:
        # Step 3: If there's a host key verification issue, resolve it
        if "REMOTE HOST IDENTIFICATION HAS CHANGED" in result[1]:
            print("Host key verification issue detected. Resolving...")
            
            # Remove offending key from known_hosts
            host_key_command = "ssh-keygen -f '/home/thakshana/.ssh/known_hosts' -R '[localhost]:2222'"
            run_command(host_key_command)

            # Re-attempt SSH connection
            result = run_command(ssh_command)

        # Step 4: If prompted to accept the new host key, accept it
        if "The authenticity of host" in result[1]:
            print("Adding new host key to known hosts.")
            result = run_command("echo 'yes' | " + ssh_command)

    # Step 5: Connect and enter password if prompted, then run a command inside the container
    try:
        # Run the SSH command again and enter password if required
        process = subprocess.Popen(
            ssh_command, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )

        # Wait for the password prompt and enter the password
        output, error = process.communicate(input="pass123\nckms --version\n")
        
        # Print the output of the ckms version command
        print("Command output:")
        print(output)
        
    except Exception as e:
        print("An error occurred:", e)


# def execute_in_docker_via_ssh(docker_command: str, password: str = "pass123") -> str:
#     """
#     Executes a specified command in a Docker container via SSH.
    
#     Parameters:
#         docker_command (str): The command to run inside the Docker container.
#         password (str): SSH password for the root user (default is "pass123").
        
#     Returns:
#         str: Output of the command executed inside Docker container.
#     """
#     # Step 1: Check if 'kms' container is running; start it if not
#     container_status = run_command("docker inspect -f '{{.State.Running}}' kms")
#     if container_status[1] != "true":
#         print("Starting 'kms' container...")
#         run_command("docker start kms")
#         time.sleep(3)  # Give time for the container to initialize

#     # Step 2: Prepare the SSH command
#     ssh_command = "ssh -o StrictHostKeyChecking=no root@localhost -p 2222"

#     # Step 3: Attempt to execute the SSH command
#     try:
#         # Launch SSH process
#         process = subprocess.Popen(
#             ssh_command, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
#         )

#         # Wait for password prompt, and send password and command
#         output, error = process.communicate(input=f"{password}\n{docker_command}\n")

#         # Check if the error indicates a host key verification issue
#         if "REMOTE HOST IDENTIFICATION HAS CHANGED" in error:
#             print("Host key verification issue detected. Resolving...")

#             # Remove offending key from known_hosts
#             clear_host_key_command = 'ssh-keygen -f "/home/thakshana/.ssh/known_hosts" -R "[localhost]:2222"'
#             run_command(clear_host_key_command)
            
#             # Retry SSH connection
#             process = subprocess.Popen(
#                 ssh_command, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
#             )
#             output, error = process.communicate(input=f"{password}\n{docker_command}\n")

#         # Print the command output or error if any
#         if output:
#             print("Command Output:")
#             print(output)
#         if error:
#             print("Command Error:")
#             print(error)

#         return output.strip() if output else error.strip()

#     except Exception as e:
#         print("An error occurred while executing command:", e)
#         return str(e)
    

def run_ssh_command(host, port, user, password, command):
    """
    Runs a specified command on a remote host via SSH.

    Parameters:
        host (str): The hostname or IP address of the remote host.
        port (int): The SSH port of the remote host.
        user (str): The username for SSH login.
        password (str): The password for SSH login.
        command (str): The command to execute on the remote host.

    Returns:
        tuple: A tuple containing the command output and any error message.
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        # Attempt to connect to the remote host
        client.connect(host, port=port, username=user, password=password)
        
        # Execute the command
        stdin, stdout, stderr = client.exec_command(command)
        
        # Read output and error messages
        output = stdout.read().decode()
        error = stderr.read().decode()
        
    except paramiko.AuthenticationException:
        return None, "Authentication failed, please verify your credentials"
    except paramiko.SSHException as ssh_exception:
        return None, f"SSH connection error: {ssh_exception}"
    except Exception as e:
        return None, f"An error occurred: {e}"
    finally:
        # Ensure the client is closed
        client.close()

    return output.strip(), error.strip()  # Return the output and error

# Usage
host = "localhost"
port = 2222
user = "root"
password = "pass123"
docker_command = "ckms sym keys create"
output, error = run_ssh_command(host, port, user, password, docker_command)
print("Command Output:", output)
print("Command Error_:", error)

