import paramiko
import time,re

client = paramiko.SSHClient()
client.load_system_host_keys()
client.set_missing_host_key_policy(paramiko.WarningPolicy)
client.connect("192.168.0.31", port=22, username="diamondjoe", password="demo")

stdin, stdout, stderr = client.exec_command("id")
print(stdout.read())

sudo_pw = "demo"
stdin, stdout, stderr = client.exec_command("sudo -S -p '' id")
stdin.write(sudo_pw + "\n")

print(stdout.read())
stdin.flush()

# channel = client.e() 
# channel.send("sudo id")       
# # wait for prompt             
# while not re.search(r".*\[sudo\].*",channel.recv(1024).decode("utf-8")): time.sleep(1)
# channel.send( "%s\n" % sudo_pw )

