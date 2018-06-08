import csv
import requests
import base64
import argparse



def print_motd():
    print ("""                         __________
Simple Tomcat Scanner

By:GBern
""")


def get_args():
    '''This function parses and return arguments passed in'''
    # Assign description to the help doc
    parser = argparse.ArgumentParser(
        description='Script retrieves schedules from a given server')
    # Add arguments
    parser.add_argument(
        '-s', '--server', type=str, help='Server name', required=False)
    parser.add_argument(
        '-p', '--port', type=str, help='Port number', required=False)
    parser.add_argument(
        '-l', '--ips', type=str, help='IP List', required=False, default=None)
    # Array for all arguments passed to script
    args = parser.parse_args()
    # Assign args to variables
    server = args.server
    port = args.port
    ips = args.ips
    # Return all variable values
    #print(server + " " + port + ' ' + ips)
    return server, port, ips

def check_manager_login(ip, port, creds):
    
    referer = ('http://' + ip + ':' + port )
    #print ('Attempting on ' + referer)
    myheaders = {'Referer': referer, 'Authorization': 'Basic ' + creds}
    responce_code = 0

    itemurl = (referer + '/manager/html')
    print("Sending Request To:  " + itemurl)
    try:
        r = requests.get(itemurl, headers=myheaders, timeout=1)
        if r.status_code in [200]:
            print("\t [+] Login successful. Status Code %d" % r.status_code)
            
        else :
            print("\t [-] No Joy. Status Code %d" % r.status_code)
    except requests.exceptions.RequestException:
        print("\t [X] Request Exception")

def readcvs(file): #pull from shodan
    with open(file) as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            feat = extract_features(row['IP'], row['Port'])
            
def checklist(file):
    files = open(file)
    var1=0
    for line in files:
        var1=var1 + 1
        print ("IP: [ %s ]" % line.strip())
    
    print ("Number of IPs = {}".format(var1))
    files.close()
    
def uselist(r_creds, r_port, ips_file):
    files = open(ips_file)
    for ip in files:
        print("\nChecking " + ip.strip())
        check_manager_login(ip.strip(), r_port, r_creds)
    
            


def extract_features(text1, text2):
    creds = gotCreds()
    check_manager_login(text1, text2, creds)
    

def gotCreds():
    
    creds = ('dG9tY2F0OnRvbWNhdA==')
    cred_option = input("\nWhich creds \n   1:tomcat:tomcat\n   2:tomcat:s3cret\n   3:Other\n")
    if cred_option == ('1'):
        creds = ('dG9tY2F0OnRvbWNhdA==')
    elif cred_option == ('2'):
        creds = ('dG9tY2F0OnMzY3JldA==')
    elif cred_option == ('3'):
        tom_user = input("Username: \t")
        tom_pass = input("Password: \t")
        tomcreds = (tom_user + ':' + tom_pass)
        b64_creds = base64.b64encode(tomcreds.encode())
        creds = b64_creds.decode("utf-8")
        #print(creds)
        
    else :
        print(cred_option + ' : Is not an option. \nReturning to getCreds... \n\n')
        gotCreds()
    
    return creds


print_motd()
server, port, ips = get_args()

if ips :
    print("Found IP File. Opening " + ips)
    checklist(ips)
    



print ("\n Curent Options")
print ("1: Scan IP list for Tomcat Login on Port " + port)
curent_options = input("\n")
if curent_options == ('1'):
    tomcreds = gotCreds()
    uselist(tomcreds, port, ips)
        




