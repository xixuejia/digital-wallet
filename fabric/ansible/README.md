# Ansible playbooks

## install and build go sdk

ansible-playbook -i hosts.ini plays/gosdk.yaml

## install and start sar proxy

ansible-playbook -i hosts.ini plays/sarproxy.yaml --extra-vars "op=install"

ansible-playbook -i hosts.ini plays/sarproxy.yaml --extra-vars "op=start"
