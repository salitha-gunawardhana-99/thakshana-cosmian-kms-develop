import init

init.check_and_install_docker()
init.check_and_install_kms()
init.setup_kms_container_ssh()
init.check_and_install_client_side_ssh()

# init.setup_client_side_ssh()
output = init.execute_in_docker_via_ssh("ckms sym keys create -t mykey")
# print("Execution result:", output)