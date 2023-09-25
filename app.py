from flask import Flask, request, jsonify, render_template, send_file
import mysql.connector
import requests
from requests.auth import HTTPBasicAuth
import winrm
import json
import csv
import os
from config import *



#-----------------------------------------AUTHENTIFICATIONS------------------------------------------
def authentificate_vmware():

    auth_url = f"https://{VCENTER_SERVER}/api/session"
    auth_payload={}
    auth_response = requests.post(auth_url, auth=HTTPBasicAuth(VCENTER_USERNAME, VCENTER_PASSWORD), json=auth_payload, verify=False)
    return(auth_response.json())


def get_hyperv_session():

    session = winrm.Session(
        HYPERV_SERVER, 
        auth=(HYPERV_USERNAME, HYPERV_PASSWORD),
        transport='ntlm',
        server_cert_validation='ignore'
    )
    return session

HYPERV_SESSION = get_hyperv_session()


def get_olvm_token():
    url = f'https://{OLVM_SERVER}/ovirt-engine/sso/oauth/token'
    data = {
        'grant_type': 'password',
        'scope': 'ovirt-app-api',
        'username': OLVM_USERNAME,
        'password': OLVM_PASSWORD
    }

    headers = {
        'Accept': 'application/json'
    }

    response = requests.post(url,headers=headers, data=data, verify=False)
    return response.json()["access_token"]



#-----------------------------------------SERVER------------------------------------------
app = Flask(__name__, static_folder="./static")

@app.route("/loginCheck", methods=["POST"])
def check():

    #-----------------------------------------USERS DATABASE------------------------------------------
    db = mysql.connector.connect(host=DATABASE_HOST, user=DATABASE_USER, password=DATABASE_PASSWORD, database=DATABASE_NAME)
    curs = db.cursor()
    req = request.get_json()
    username = req["username"]
    pwd = req["pwd"]

    curs.execute(f"select * from users where(username='{username}' and pwd='{pwd}')")
    data = curs.fetchall() 
    if data:
        resp = True
    else:
        resp = False

    curs.close()
    db.close()
        
    return jsonify({"status":resp})


#-----------------------------------------VMWARE------------------------------------------
@app.route("/getVmsVmware", methods=["GET", "POST"])
def getVmsVmware():

    auth_token = authentificate_vmware()

    headers = {
        "Content-Type": "application/json",
        "vmware-api-session-id": auth_token
    }

    folder_url = f"https://{VCENTER_SERVER}/api/vcenter/folder"

    folders_response = requests.get(folder_url, headers=headers, verify=False)
    folders_data = folders_response.json()

    folder_list = []
    for f in folders_data:
        if f["type"] == "VIRTUAL_MACHINE":
            folder_list.append(f)

    resp = {}
    for f in folder_list:

        folder_id = f["folder"]
        folder_name = f["name"]
        auth_token = authentificate_vmware()
        headers = {
            "Content-Type": "application/json",
            "vmware-api-session-id": auth_token
        }

        vm_url = f"https://{VCENTER_SERVER}/api/vcenter/vm?folders={folder_id}"

        vm_response = requests.get(vm_url, headers=headers, verify=False)
        vm_data = vm_response.json()

        vm = []
        for v in vm_data:
            vm.append(v)
        
        resp[folder_name] = vm

    return jsonify(resp, folder_list)

@app.route("/getVmInfoVmware", methods=["GET", "POST"])
def getVmInfoVmware():
    auth_token = authentificate_vmware()

    req = request.get_json()
    vmId = req["id"]

    vm_url = f"https://{VCENTER_SERVER}/api/vcenter/vm/{vmId}"
    headers = {
        "Content-Type": "application/json",
        "vmware-api-session-id": auth_token
    }

    vm_response = requests.get(vm_url, headers=headers, verify=False)
    vm_data = vm_response.json()

    auth_token = authentificate_vmware()
    headers = {
        "Content-Type": "application/json",
        "vmware-api-session-id": auth_token
    }
    
    ip_url = f"https://{VCENTER_SERVER}/api/vcenter/vm/{vmId}/guest/identity"
    ip_resp = requests.get(ip_url, headers=headers, verify=False)
    ip_data = ip_resp.json()

    if "ip" in ip_data.keys():
        vm_data["ip"] = ip_data
    else:
        vm_data["ip"] = "None"

    storage = []
    for s in vm_data["disks"]:
        storage.append([vm_data["disks"][s]["backing"]["vmdk_file"].split()[0], int(vm_data["disks"][s]["capacity"])/(1024**3)])

    vm_data["storage"] = storage

    return jsonify(vm_data)


@app.route("/getFolderInfoVmware", methods=["GET", "POST"])
def getFolderInfoVmware():

    req = request.get_json()
    folderId = req["id"]

    auth_token = authentificate_vmware()
    headers = {
        "Content-Type": "application/json",
        "vmware-api-session-id": auth_token
    }
    
    vm_url = f"https://{VCENTER_SERVER}/api/vcenter/vm?folders={folderId}"

    response = requests.get(vm_url, headers=headers, verify=False)
    data = {"folders":response.json()}

    ram = 0
    cpu = 0
    storage = []
    for v in data["folders"]:
        id = v["vm"]
        auth_token = authentificate_vmware()
        vm_url = f"https://{VCENTER_SERVER}/api/vcenter/vm/{id}"
        headers = {
            "Content-Type": "application/json",
            "vmware-api-session-id": auth_token
        }
        vm_response = requests.get(vm_url, headers=headers, verify=False)
        vm_data = vm_response.json()

        
        for s in vm_data["disks"]:
            storage.append([vm_data["disks"][s]["backing"]["vmdk_file"].split()[0], int(vm_data["disks"][s]["capacity"])/(1024**3)])

        ram += vm_data["memory"]["size_MiB"]

        cpu += vm_data["cpu"]["count"]

    data["storage"] = storage
    data["memory"] = ram
    data["cpu"] = cpu


    return(data)

#-----------------------------------------HYPERV------------------------------------------

@app.route("/getVmsHyperV", methods=["GET","POST"])
def getFoldersHyperV():

    script = '''
        $vms = Get-VM
        $vmNames = $vms | ForEach-Object { $_.Name }
        $vmIds = $vms | ForEach-Object{ $_.Id }
        $vmInfo = [PSCustomObject]@{
            'name' = $vmNames
            'id' = $vmIds
        }
        $vmInfo | ConvertTo-Json

    '''
    result = HYPERV_SESSION.run_ps(script)
    all_vms = json.loads(result.std_out.decode('utf-8'))
    res = []
    for i in range(0, len(all_vms["name"])):
        res.append({"name":all_vms["name"][i], "id":all_vms["id"][i]})

    all_vms = res

    folderScript='''
    $folders = Get-VMGroup | Where-Object {$_.GroupType -eq "VMCollectionType"}
    $ids = $folders | ForEach-Object { $_.InstanceId }
    $names = $folders | ForEach-Object { $_.Name }
    $info = [PSCustomObject]@{
        'id' = $ids
        'name' = $names
    }
    $info | ConvertTo-Json
    
    '''

    result = HYPERV_SESSION.run_ps(folderScript)
    foldersInfo = json.loads(result.std_out.decode('utf-8'))

    vmFolderList = {}

    for name in foldersInfo["name"]:

        script = '''
        $grp = Get-VMGroup -Name '''+ name +'''
        $vmNames = $grp.VMMembers | ForEach-Object { $_.Name }
        $vmIds = $grp.VMMembers | ForEach-Object{ $_.Id }
        $vmInfo = [PSCustomObject]@{
            'name' = $vmNames
            'id' = $vmIds
        }
        $vmInfo | ConvertTo-Json
        '''

        result = HYPERV_SESSION.run_ps(script)
        vmsInfo = json.loads(result.std_out.decode('utf-8'))


        res = []

        for i in range(0, len(vmsInfo["name"])):
            info = {"name":vmsInfo["name"][i], "id":vmsInfo["id"][i]}
            res.append(info) 
            if info in all_vms:
                all_vms.remove(info)

        vmFolderList[name] = res

    vmFolderList["vms with no group"] = all_vms
    

    res = []
    for i in range(0, len(foldersInfo["name"])):
        res.append({"name":foldersInfo["name"][i], "id":foldersInfo["id"][i]}) 

    foldersInfo = res

    return jsonify(vmFolderList, foldersInfo)



@app.route("/getVmInfoHyperV", methods=["GET","POST"])
def getVmInfoHyperV():

    req = request.get_json()
    vmId = req["id"]

    script = '''
    $types = @()
    $sizes = @()

    $vm = Get-VM -Id '''+vmId+'''
    $disks = (Get-VMHardDiskDrive -VM $vm)
    $sizes += (Get-VHD -Path $disks.path) | ForEach-Object { $_.Size / (1024*1024*1024) }
    $types += $disks.PoolName
    $storage = [PSCustomObject]@{
        'size' = $sizes
        'type' = $types
    }

    $vmInfo = [PSCustomObject]@{
        'name' = $vm.Name
        'id' = $vm.Id
        'memory' = $vm.MemoryStartup
        'cpu' = $vm.ProcessorCount
        'power_state' = $vm.State
        'storage' = $storage
    }
    $vmInfo | ConvertTo-Json
    '''

    result = HYPERV_SESSION.run_ps(script)
    vmsInfo = json.loads(result.std_out.decode('utf-8'))
    print(vmsInfo)
    res = []
    for i in range(len(vmsInfo["storage"]["size"])):
        res.append([vmsInfo["storage"]["type"][i], vmsInfo["storage"]["size"][i]])

    vmsInfo["storage"] = res
    
    return jsonify(vmsInfo)


@app.route("/getFolderInfoHyperV", methods=["GET","POST"])
def getFolderInfoHyperV():

    req = request.get_json()
    folderId = req["id"]

    script = '''
    $group = Get-VMGroup -Id '''+folderId+'''

    $vmGroupVms = $group.VMMembers

    $totalCPUCount = 0
    $totalMemorySize = 0
    $types = @()
    $sizes = @()


    foreach ($vm in $vmGroupVMs) {
        $totalCPUCount += $vm.ProcessorCount
        $totalMemorySize += $vm.MemoryStartup
        $disks = (Get-VMHardDiskDrive -VM $vm)
        $s = (Get-VHD -Path $disks.path) | ForEach-Object { $_.Size / (1024*1024*1024) }
        $t = $disks.PoolName
        $types += $t
        $sizes += $s
    }

    $names = $vmGroupVms | ForEach-Object { $_.Name }

    $folderInfo = [PSCustomObject]@{
        'vms' = $names
        'memory' = $totalMemorySize
        'cpu' = $totalCPUCount
        'types' = $types
        'sizes' = $sizes
    }
    $folderInfo | ConvertTo-Json
    '''


    result = HYPERV_SESSION.run_ps(script)
    folderInfo = json.loads(result.std_out.decode('utf-8'))

    res = []
    for i in range(len(folderInfo["sizes"])):
        res.append([folderInfo["types"][i], folderInfo["sizes"][i]])

    folderInfo["storage"] = res


    return jsonify(folderInfo)


#-----------------------------------------OLVM------------------------------------------
@app.route("/getVmsOLVM", methods=["GET","POST"])
def getVmsOLVM():

    token = get_olvm_token()
    headers = {
        'Authorization': f'Bearer {token}',
        'Accept': 'application/json'
    }
    url = f'http://{OLVM_SERVER}/ovirt-engine/api/clusters'
    resp = requests.get(url, headers=headers, verify=False).json()["cluster"]

    for c in resp:

        token = get_olvm_token()
        headers = {
            'Authorization': f'Bearer {token}',
            'Accept': 'application/json'
        }
        url = f'http://{OLVM_SERVER}/ovirt-engine/api/clusters/{c["id"]}/affinitygroups'
        groups = requests.get(url, headers=headers, verify=False).json()["affinity_group"]

        group_res = []
        for gr in groups:
            group_res.append({"name":gr["name"], "id":gr["id"]})

    other_vms = []
    token = get_olvm_token()
    headers = {
        'Authorization': f'Bearer {token}',
        'Accept': 'application/json'
    }
    url = f'http://{OLVM_SERVER}/ovirt-engine/api/vms'
    response = requests.get(url, headers=headers, verify=False).json()["vm"]
    for resp in response:
        other_vms.append({"name":resp["name"], "id":resp["id"]})

    res = {}
    for g in groups:

        vms = []
        for vm in g["vms"]["vm"]:
            token = get_olvm_token()
            headers = {
                'Authorization': f'Bearer {token}',
                'Accept': 'application/json'
            }
            url = f'http://{OLVM_SERVER}{vm["href"]}'
            resp = requests.get(url, headers=headers, verify=False).json()
            v = {"name":resp["name"], "id":resp["id"]}
            vms.append(v)

            if v in other_vms:
                other_vms.remove(v)
        
        res[g["name"]] = vms
        res["vms with no group"] = other_vms

    return jsonify(res, group_res)

@app.route("/getVmInfoOLVM", methods=["GET","POST"])
def getVmInfoOLVM():

    req = request.get_json()
    vmId = req["id"]

    token = get_olvm_token()
    headers = {
        'Authorization': f'Bearer {token}',
        'Accept': 'application/json'
    }
    url = f'http://{OLVM_SERVER}/ovirt-engine/api/vms/{vmId}?follow=disk_attachments.disk'
    response = requests.get(url, headers=headers, verify=False).json()

    if "address" not in response["display"]:
        response["display"]["address"] = "None"

    
    res = []
    for disk_attachment in response['disk_attachments']['disk_attachment']:
        size  = int(disk_attachment['disk']['provisioned_size'])//(1024**3)
        storage_domain_href = disk_attachment["disk"]["storage_domains"]["storage_domain"][0]["href"]
        token = get_olvm_token()
        headers = {
            'Authorization': f'Bearer {token}',
            'Accept': 'application/json'
        }
        t = requests.get(f'http://{OLVM_SERVER}{storage_domain_href}', headers=headers, verify=False).json()["name"]
        res.append([t , size])

    response["storage"] = res
    

    return response
    
@app.route("/getFolderInfoOLVM",methods=["GET","POST"])
def getFolderInfoOLVM():

    req = request.get_json()
    folderId = req["id"]

    token = get_olvm_token()
    headers = {
        'Authorization': f'Bearer {token}',
        'Accept': 'application/json'
    }
    url = f'http://{OLVM_SERVER}/ovirt-engine/api/clusters'
    resp = requests.get(url, headers=headers, verify=False).json()["cluster"]

    vm_ids = []
    for c in resp:

        token = get_olvm_token()
        headers = {
            'Authorization': f'Bearer {token}',
            'Accept': 'application/json'
        }
        url = f'http://{OLVM_SERVER}/ovirt-engine/api/clusters/{c["id"]}/affinitygroups/{folderId}'
        vm_resp = requests.get(url, headers=headers, verify=False).json()["vms"]["vm"]
        for i in vm_resp:
            vm_ids.append(i["id"])

    vms=[]
    cpu_res = 0
    ram_res = 0
    storage_res = []

    for i in vm_ids:

        token = get_olvm_token()
        headers = {
            'Authorization': f'Bearer {token}',
            'Accept': 'application/json'
        }
        url = f'http://{OLVM_SERVER}/ovirt-engine/api/vms/{i}?follow=disk_attachments.disk'
        vm = requests.get(url, headers=headers, verify=False).json()

        for disk_attachment in vm['disk_attachments']['disk_attachment']:
            size  = int(disk_attachment['disk']['provisioned_size'])//(1024**3)
            storage_domain_href = disk_attachment["disk"]["storage_domains"]["storage_domain"][0]["href"]
            token = get_olvm_token()
            headers = {
                'Authorization': f'Bearer {token}',
                'Accept': 'application/json'
            }
            t = requests.get(f'http://{OLVM_SERVER}{storage_domain_href}', headers=headers, verify=False).json()["name"]
            storage_res.append([t , size])

        cpu_res += int(vm["cpu"]["topology"]["cores"])
        ram_res += int(vm["memory"])/(1024**2)
        vms.append(vm["name"])

    data = {}
    data["storage"] = storage_res
    data["memory"] = ram_res
    data["cpu"] = cpu_res
    data["vms"] = vms

    return jsonify(data)
    

@app.route('/')
def index():
    return render_template('index.html')

#-----------------------------------------CSV FILES------------------------------------------
@app.route("/getCSVOLVM", methods=["GET","POST"])
def getCSVOLVM():

    req = request.get_json()
    folderId = req["id"]

    token = get_olvm_token()
    headers = {
        'Authorization': f'Bearer {token}',
        'Accept': 'application/json'
    }
    url = f'http://{OLVM_SERVER}/ovirt-engine/api/clusters'
    resp = requests.get(url, headers=headers, verify=False).json()["cluster"]

    vm_ids = []
    for c in resp:

        token = get_olvm_token()
        headers = {
            'Authorization': f'Bearer {token}',
            'Accept': 'application/json'
        }
        url = f'http://{OLVM_SERVER}/ovirt-engine/api/clusters/{c["id"]}/affinitygroups/{folderId}'
        vm_resp = requests.get(url, headers=headers, verify=False).json()["vms"]["vm"]
        for i in vm_resp:
            vm_ids.append(i["id"])

    csvRes = []

    for i in vm_ids:
        token = get_olvm_token()
        headers = {
            'Authorization': f'Bearer {token}',
            'Accept': 'application/json'
        }
        url = f'http://{OLVM_SERVER}/ovirt-engine/api/vms/{i}?follow=disk_attachments.disk'
        response = requests.get(url, headers=headers, verify=False).json()

        if "address" not in response["display"]:
            response["display"]["address"] = "None"

        
        res = []
        for disk_attachment in response['disk_attachments']['disk_attachment']:
            size  = int(disk_attachment['disk']['provisioned_size'])//(1024**3)
            storage_domain_href = disk_attachment["disk"]["storage_domains"]["storage_domain"][0]["href"]
            token = get_olvm_token()
            headers = {
                'Authorization': f'Bearer {token}',
                'Accept': 'application/json'
            }
            t = requests.get(f'http://{OLVM_SERVER}{storage_domain_href}', headers=headers, verify=False).json()["name"]
            res.append([t , size])

        response["storage"] = res

        csvRes.append({"VM Name":response["name"],
                       "VM Id":i,
                       "Memory":int(response["memory"])/(1024**2),
                       "CPU":response["cpu"]["topology"]["cores"],
                       "Storage":response["storage"]})
        

    if os.path.isfile(csv_file_path):
        os.remove(csv_file_path)

    fields = ["VM Name", "VM Id", "Memory", "CPU", "Storage"]

    with open(csv_file_path, 'w', newline='') as file: 
        writer = csv.DictWriter(file, fieldnames = fields)
        writer.writeheader() 
        writer.writerows(csvRes)

    return send_file(csv_file_path, as_attachment=True)

@app.route("/getCSVHyperV", methods=["GET","POST"])
def getCSVHyperV():

    req = request.get_json()
    folderId = req["id"]

    script = '''
    $group = Get-VMGroup -Id '''+folderId+'''

    $vmGroupVmIds = $group.VMMembers.Id
    
    $res = [PSCustomObject]@{
        'ids' = $vmGroupVmIds
    }
    $res | ConvertTo-Json

    '''

    result = HYPERV_SESSION.run_ps(script)
    vmIds = json.loads(result.std_out.decode('utf-8'))

    csvRes = []
    for id in vmIds["ids"]:

        script = '''
        $types = @()
        $sizes = @()

        $vm = Get-VM -Id '''+id+'''
        $disks = (Get-VMHardDiskDrive -VM $vm)
        $sizes += (Get-VHD -Path $disks.path) | ForEach-Object { $_.Size / (1024*1024*1024) }
        $types += $disks.PoolName
        $storage = [PSCustomObject]@{
            'size' = $sizes
            'type' = $types
        }

        $vmInfo = [PSCustomObject]@{
            'name' = $vm.Name
            'id' = $vm.Id
            'memory' = $vm.MemoryStartup
            'cpu' = $vm.ProcessorCount
            'power_state' = $vm.State
            'storage' = $storage
        }
        $vmInfo | ConvertTo-Json
        '''

        result = HYPERV_SESSION.run_ps(script)
        vmsInfo = json.loads(result.std_out.decode('utf-8'))

        res = []
        for i in range(len(vmsInfo["storage"]["size"])):
            res.append([vmsInfo["storage"]["type"][i], vmsInfo["storage"]["size"][i]])

        vmsInfo["storage"] = res
    
        csvRes.append({"VM Name":vmsInfo["name"],
                        "VM Id":vmsInfo["id"],
                        "Memory":int(vmsInfo["memory"])/(1024**2),
                        "CPU":vmsInfo["cpu"],
                        "Storage":vmsInfo["storage"]})
        

    if os.path.isfile(csv_file_path):
        os.remove(csv_file_path)

    fields = ["VM Name", "VM Id", "Memory", "CPU", "Storage"]

    with open(csv_file_path, 'w', newline='') as file: 
        writer = csv.DictWriter(file, fieldnames = fields)
        writer.writeheader() 
        writer.writerows(csvRes)

    return send_file(csv_file_path, as_attachment=True)

@app.route("/getCSVVmware", methods=["GET","POST"])
def getCSVVmware():
    req = request.get_json()
    folderId = req["id"]

    auth_token = authentificate_vmware()
    headers = {
        "Content-Type": "application/json",
        "vmware-api-session-id": auth_token
    }
    
    vm_url = f"https://{VCENTER_SERVER}/api/vcenter/vm?folders={folderId}"

    response = requests.get(vm_url, headers=headers, verify=False)
    data = {"folders":response.json()}

    csvRes = []
    for v in data["folders"]:
        id = v["vm"]
        auth_token = authentificate_vmware()
        vm_url = f"https://{VCENTER_SERVER}/api/vcenter/vm/{id}"
        headers = {
            "Content-Type": "application/json",
            "vmware-api-session-id": auth_token
        }
        vm_response = requests.get(vm_url, headers=headers, verify=False)
        vm_data = vm_response.json()

        storage = []
        for s in vm_data["disks"]:
            storage.append([vm_data["disks"][s]["backing"]["vmdk_file"].split()[0], int(vm_data["disks"][s]["capacity"])/(1024**3)])


        csvRes.append({"VM Name":vm_data["name"],
                        "VM Id":id,
                        "Memory":int(vm_data["memory"]["size_MiB"]),
                        "CPU":vm_data["cpu"]["count"],
                        "Storage":storage})
        
    if os.path.isfile(csv_file_path):
        os.remove(csv_file_path)

    fields = ["VM Name", "VM Id", "Memory", "CPU", "Storage"]

    with open(csv_file_path, 'w', newline='') as file: 
        writer = csv.DictWriter(file, fieldnames = fields)
        writer.writeheader() 
        writer.writerows(csvRes)

    return send_file(csv_file_path, as_attachment=True)

@app.route("/getServers", methods=["GET"])
def getServers():
    res = {"vmware":[VCENTER_SERVER, VCENTER_USERNAME, VCENTER_PASSWORD],
            "hyperv":[HYPERV_SERVER, HYPERV_USERNAME, HYPERV_PASSWORD],
            "olvm":[OLVM_SERVER, OLVM_USERNAME, OLVM_PASSWORD],
            "status":"success"}
    
    return jsonify(res)

@app.route("/setServers", methods=["GET","POST"])
def setServers():

    req = request.get_json()
    t = req["type"]
    server = req["server"]
    username = req["username"]
    password = req["password"]

    status="success"
    
    if t == "vmware":
        global VCENTER_SERVER, VCENTER_USERNAME, VCENTER_PASSWORD
        auth_url = f"https://{server}/api/session"
        auth_payload={}
        if requests.post(auth_url, auth=HTTPBasicAuth(username, password), json=auth_payload, verify=False).status_code == 201:
            VCENTER_SERVER = server
            VCENTER_USERNAME = username
            VCENTER_PASSWORD = password
            status = "success"
        else:
            status = "error"

    elif t == "hyperv":
        try:
            session = winrm.Session(
                server, 
                auth=(username, password),
                transport='ntlm',
                server_cert_validation='ignore'
            )
            
            if (session.run_ps("echo 'test'").status_code == 200):
                global HYPERV_SERVER, HYPERV_USERNAME, HYPERV_PASSWORD, HYPERV_SESSION
                HYPERV_SERVER = server
                HYPERV_USERNAME = username
                HYPERV_PASSWORD = password
                HYPERV_SESSION = get_hyperv_session()
                status="success"
        except:
            status = "error"

    else:
        url = f'https://{server}/ovirt-engine/sso/oauth/token'
        data = {
            'grant_type': 'password',
            'scope': 'ovirt-app-api',
            'username': username,
            'password': password
        }
        headers = {
            'Accept': 'application/json'
        }

        if (requests.post(url,headers=headers, data=data, verify=False).status_code == 200):
            global OLVM_SERVER, OLVM_USERNAME, OLVM_PASSWORD
            OLVM_SERVER =  server
            OLVM_USERNAME = username
            OLVM_PASSWORD = password
            status = "success"
        else:
            status = "error"

    res = {"vmware":[VCENTER_SERVER, VCENTER_USERNAME, VCENTER_PASSWORD],
            "hyperv":[HYPERV_SERVER, HYPERV_USERNAME, HYPERV_PASSWORD],
            "olvm":[OLVM_SERVER, OLVM_USERNAME, OLVM_PASSWORD],
            "status":status}
    
    return jsonify(res)


@app.route("/test", methods=["GET", "POST"])
def test():
    pass



app.run()

