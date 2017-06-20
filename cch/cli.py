# -*- coding: utf-8 -*-

from __future__ import print_function
import boto3
import botocore
from builtins import input
import click
import prettytable
import sys

# All ebs image, not instance-store. All latest ubuntu 12.04, but version not
# specified. Maybe need to get from amazon
images = {
    'ap-southeast-1': {'ubuntu14': 'ami-21d30f42'},     # Singapore
    'ap-south-1': {'ubuntu14': 'ami-4a90fa25'},         # Mumbai
    'us-east-1': {'ubuntu14': 'ami-2d39803a'},          # nvirginia
    'us-west-1': {'ubuntu14': 'ami-48db9d28'},          # northcalif
    'us-west-2': {'ubuntu14': 'ami-d732f0b7'},          # oregon
    'eu-west-1': {'ubuntu14': 'ami-ed82e39e'},          # ireland
    'eu-central-1': {'ubuntu14': 'ami-26c43149'},       # frankfurt
    'ap-northeast-1': {'ubuntu14': 'ami-a21529cc'},     # tokyo
    'ap-northeast-2': {'ubuntu14': 'ami-09dc1267'},     # seoul
    'ap-southeast-2': {'ubuntu14': 'ami-ba3e14d9'},     # sydney
    'sa-east-1': {'ubuntu14': 'ami-dc48dcb0'},          # saopaolo
}

def get_connection():
    """Ensures that the AWS is configured properly.

    If not, tell how to configure it.

    Returns connection object if configured properly, else None.
    """
    try:
        ec2 = boto3.resource('ec2')
    except (botocore.exceptions.NoRegionError,
            botocore.exceptions.NoCredentialsError) as e:
        # TODO(rushiagr): instead of telling people to run credentials, ask
        # credentials here itself
        print('Credentials and region not configured? Run "aws configure" to configure it.')
        # TODO(rushiagr): let people provide singapore, and guess region name from
        # that.
        print('Provide region as "ap-southeast-1" for Singapore.')
        return None
    return ec2

def get_region_specific_ami_id(distro):
    region = boto3.session.Session().region_name
    return images.get(region).get(distro)

def abort_if_false(ctx, param, value):
    if not value:
        ctx.abort()

@click.command()
@click.option('-s', 'show_vol_info', flag_value=True,
        help='Show VM disk sizes (GBs), starting with root disk')
@click.option('-n', 'filter_name',
        help='Show only VMs which matches given string (case-insensitive)')
def lsvm(show_vol_info, filter_name):
    '''List all EC2 VMs. '''
    ec2 = get_connection()
    if not ec2:
        return

    filter_name = filter_name.lower() if filter_name else None

    if show_vol_info:
        table = prettytable.PrettyTable(
                ['ID', 'Name', 'Status', 'Flavor', 'IP', 'Vols(GB)'])
    else:
        table = prettytable.PrettyTable(
                ['ID', 'Name', 'Status', 'Flavor', 'IP', 'Vols'])

    table.left_padding_width=0
    table.right_padding_width=1
    table.border=False

    instances = ec2.instances.all()

    instances_to_print = []

    if not filter_name:
        instances_to_print = instances
    else:
        for i in instances:
            if i.tags is not None and len(i.tags) > 0:
                for tag in i.tags:
                    if(tag['Key'] == 'Name' and
                            tag['Value'].lower().find(filter_name) > -1):
                        instances_to_print.append(i)
                        break

    for i in instances_to_print:
        row = [
                i.id,
                i.tags[0]['Value'] if i.tags is not None else '',
                i.state['Name'],
                i.instance_type,
                i.public_ip_address]
        if show_vol_info:
            row.append([vol.size for vol in i.volumes.all()])
        else:
            row.append(len(i.block_device_mappings))
        table.add_row(row)

    print(table.get_string(sortby='Status'))

@click.command()
def mkvm():
    # get a connection to ec2 or die
    ec2 = boto3.client('ec2')
    if not ec2:
        return

    # get the available regions for ec2 and save them as a list
    region_names = []
    regions = ec2.describe_regions()

    for region in regions['Regions']:
        region_names.append(region['RegionName'])
    
    # prompt for a region, offering the current region as the default
    selected_region = boto3.session.Session().region_name
    
    while True:
        sys.stdout.write("Select region ['l' to list; ENTER to use default, %s]: " % selected_region)
        region=input()
        if region.lower() == 'l':
            print("Available regions:",end='\n\t')
            print(*region_names,sep='\n\t')
            continue
        elif region in region_names:
            selected_region = region
            break
        elif not region:
            break
        else:
            print('Invalid region.')
            return

    # define the available instance types (needs to be automated with a scraper)
    flavor_names = ['t2.nano', 't2.micro', 't2.small', 't2.medium', 
                    't2.large', 't2.xlarge', 't2.2xlarge', 'm4.large', 
                    'm4.xlarge', 'm4.2xlarge', 'm4.4xlarge', 'm4.10xlarge', 
                    'm4.16xlarge', 'm3.medium', 'm3.large', 'm3.xlarge', 
                    'm3.2xlarge', 'c4.large', 'c4.xlarge', 'c4.2xlarge', 
                    'c4.4xlarge', 'c4.8xlarge', 'c3.large', 'c3.xlarge', 
                    'c3.2xlarge', 'c3.4xlarge', 'c3.8xlarge', 'p2.xlarge', 
                    'p2.8xlarge', 'p2.16xlarge', 'g2.2xlarge', 'g2.8xlarge', 
                    'x1.16large', 'x1.32xlarge', 'r4.large', 'r4.xlarge', 
                    'r4.2xlarge', 'r4.4xlarge', 'r4.8xlarge', 'r4.16xlarge', 
                    'r3.large', 'r3.xlarge', 'r3.2xlarge', 'r3.4xlarge', 
                    'r3.8xlarge', 'i3.large', 'i3.xlarge', 'i3.2xlarge', 
                    'i3.4xlarge', 'i3.8xlarge', 'i3.16large', 'd2.xlarge', 
                    'd2.2xlarge', 'd2.4xlarge', 'd2.8xlarge', 'f1.2xlarge', 
                    'f1.16xlarge']

    # prompt for a flavor, offering an acceptable default
    selected_flavor = 't2.micro'
    
    while True:
        sys.stdout.write("Select flavor ['l' to list; ENTER to use default, %s]: " % selected_flavor)
        flavor=input()
        if flavor.lower() == 'l':
            print("Available flavors:",end='\n\t')
            print(*flavor_names,sep='\n\t')
            continue
        elif flavor in flavor_names:
            selected_flavor = flavor
            break
        elif not flavor:
            break
        else:
            print('Invalid flavor name.')
            return

    # get the available keys
    keypair_names = []
    keypairs = ec2.describe_key_pairs()

    for key in keypairs['KeyPairs']:
        keypair_names.append(key['KeyName'])

    print('Available key pairs:',end='\n\t')
    print(*keypair_names,sep='\n\t')
    sys.stdout.write("Select keypair [ENTER for no keypair]: ")
    selected_keypair=input()

    # get the available security groups
    secgroup_names = []
    secgroups = ec2.describe_security_groups()
    
    for sg in secgroups['SecurityGroups']:
        secgroup_names.append(sg['GroupName'])

    print('Available security groups:',end='\n\t')
    print(*secgroup_names,sep='\n\t')
    sys.stdout.write("Select security group [ENTER for no security group]: ")
    selected_security_group_name=input()

    sys.stdout.write("Enter root volume size in GBs: ")
    selected_vol_size=input()

    ami_id = get_region_specific_ami_id('ubuntu14')

    if ami_id is None:
        print('We do not have Ubuntu image for this region')
        return

    if not selected_security_group_name:
        ec2.run_instances(DryRun=False, ImageId=ami_id, MinCount=1,
                MaxCount=1, KeyName=selected_keypair, InstanceType=selected_flavor,
                BlockDeviceMappings=[{'DeviceName': '/dev/sda1',
                    'Ebs': {"VolumeSize": int(selected_vol_size)}}])
    else:
        ec2.run_instances(DryRun=False, ImageId=ami_id, MinCount=1,
                MaxCount=1, KeyName=selected_keypair, InstanceType=selected_flavor,
                BlockDeviceMappings=[{'DeviceName': '/dev/sda1',
                    'Ebs': {"VolumeSize": int(selected_vol_size)}}],
                SecurityGroupIds=[selected_security_group_name])

@click.command()
def lskp():
    ec2 = get_connection()
    if not ec2:
        return

    keypairs = ec2.key_pairs.all()
    keypair_names = [kp.name for kp in keypairs]
    print('Available keypairs:\n   ', '\n    '.join(keypair_names))

@click.command()
def lsimg():
    ec2 = get_connection()
    if not ec2:
        return
    client = boto3.client('ec2')
    images = client.describe_images(Owners=['self'])
    image_id_names = [i['ImageId']+' '+i['Name'] for i in images['Images']]
    print('Images:\n   ', '\n    '.join(image_id_names))


@click.command()
@click.option('-a', 'is_detail', flag_value=True,
        help='Show security group rules.')
def lssg(is_detail):
    ec2 = get_connection()
    if not ec2:
        return

    secgroups = list(ec2.security_groups.all())
    if not is_detail:
        secgroup_names = [sg.group_name for sg in secgroups]
        print('Available security groups:\n   ', '\n    '.join(secgroup_names))
        print('\nExecute "lssg -a" for viewing security group rules')
    else:
        for sg in secgroups:
            print('\nSecurity group: Name:', sg.group_name, 'ID:', sg.id,
                    'Description:', sg.description)

            ip_permissions = sg.ip_permissions
            print('   Protocol\t  IP\t\tfrom\tto')
            for perm in ip_permissions:
                if perm['IpRanges']:
                    print('     tcp\t' + perm['IpRanges'][0]['CidrIp'] + '\t' +
                        str(perm['FromPort']) + '\t' + str(perm['ToPort']))

@click.command()
@click.argument('vm_ids', nargs=-1, required=True)
@click.option('--yes', is_flag=True, callback=abort_if_false,
              expose_value=False,
              prompt='Are you sure you want to stop and terminate the VM/VMs?'
                ' You can stop the VM by using "stpvm" command.')
def rmvm(vm_ids):

    # TODO(rushiagr): not required as we're already checking 'required=True'
    if len(vm_ids) == 0:
        print('No VM IDs provided. Aborting')
        return

    print('Stopping and terminating VMs with IDs: ', vm_ids)

    # TODO(rushiagr): use re.match('i-[0-9a-f]+', 'i-abcd1334') to confirm
    # it's an ID

    ec2 = get_connection()
    if not ec2:
        return

    ec2.instances.filter(InstanceIds=vm_ids).stop()
    ec2.instances.filter(InstanceIds=vm_ids).terminate()

@click.command()
@click.argument('vm_ids', nargs=-1, required=True)
@click.option('--yes', is_flag=True, callback=abort_if_false,
              expose_value=False,
              prompt='Are you sure you want to stop the VM?')
def stpvm(vm_ids):
    print('Stopping (but not terminating) VMs with IDs: ', vm_ids)

    # TODO(rushiagr): not required as we're already checking 'required=True'
    if len(vm_ids) == 0:
        print('No VM IDs provided. Aborting')
        return

    # TODO(rushiagr): use re.match('i-[0-9a-f]+', 'i-abcd1334') to confirm
    # it's an ID

    ec2 = get_connection()
    if not ec2:
        return

    ec2.instances.filter(InstanceIds=vm_ids).stop()

@click.command()
def mkkp():
    ec2 = get_connection()
    if not ec2:
        return
    sys.stdout.write("Keypair name (required): ")
    keypair_name=input()
    kp = ec2.create_key_pair(KeyName=keypair_name)
    print('Keypair', keypair_name, 'created. Private key:')
    print(kp.key_material)

@click.command()
@click.argument('keypair_name', required=False)
@click.option('--yes', is_flag=True, callback=abort_if_false,
              expose_value=False,
              prompt='Are you sure you want to delete the keypair?')
def rmkp(keypair_name):
    ec2 = get_connection()
    if not ec2:
        return

    if keypair_name is None:
        sys.stdout.write("Keypair name (required): ")
        keypair_name=input()

    kp = ec2.KeyPair(keypair_name)
    kp.delete()
    print('Keypair', keypair_name, 'deleted.')

@click.command()
def mksg():
    ec2 = get_connection()
    if not ec2:
        return

    sys.stdout.write("Note that only TCP rules are supported as of now.\n")

    sys.stdout.write("Security group name (required): ")
    sg_name=input()
    sys.stdout.write("Security group description (required): ")
    sg_description=input()

    ip_portrange_tuples = []

    while True:
        sys.stdout.write("Add security group rule? [y/n]: ")
        bool_inp = input()
        if bool_inp.lower().startswith('y'):
            sys.stdout.write("IP (e.g. 0.0.0.0/0): ")
            ip = input()
            sys.stdout.write("Port or port range (e.g. '8080' or '8000-8999': ")
            port_range = input()
            if port_range.find('-') > -1:
                start_port, end_port = port_range.split('-')
            else:
                start_port = end_port = port_range
            start_port, end_port = int(start_port), int(end_port)
            if start_port > end_port:
                start_port, end_port = end_port, start_port
            ip_portrange_tuples.append((ip, start_port, end_port))
        else:
            break

    mysg = ec2.create_security_group(GroupName=sg_name,
            Description=sg_description)
    for ip, start_port, end_port in ip_portrange_tuples:
        mysg.authorize_ingress(IpProtocol="tcp", CidrIp=ip,
                FromPort=start_port, ToPort=end_port)

    print('Security group', sg_name, 'created')

@click.command()
@click.argument('secgroup_name', required=False)
@click.option('--yes', is_flag=True, callback=abort_if_false,
              expose_value=False,
              prompt='Are you sure you want to delete the security group?')
def rmsg(secgroup_name):
    ec2 = get_connection()
    if not ec2:
        return

    if secgroup_name is None:
        sys.stdout.write("Security group name (required): ")
        secgroup_name=input()

    sg = [sg for sg in ec2.security_groups.filter(GroupNames=[secgroup_name])][0]
    sg.delete()
    print('Security group', secgroup_name, 'deleted.')
