#!/usr/bin/env python3
'''
Created on Aug 26, 2016

@author: jmmunoz

    TO DO: 
        - SSH command failing
        - Logging improving
        - Testing
            - Parametro time between commands
            - Parametro time to get configuration
        
        fawstvpn
    
'''

import paramiko
import time
import boto3
import xml.etree.ElementTree as ET
import argparse
import configparser
import logging
import re
import os
from fileinput import filename

def main():
    time_between_commands = 0.100
    time_to_get_config = 1
    
    logging.basicConfig(format='%(module)s: %(levelname)s %(message)s', level=logging.INFO)
    logging.info('Starting...')
    
    # Set default config
    config = addDefaultConfig()
    
    # Get command line configuration
    config = {**config, **getCmdConfig()}
    
    # Get the configuration in the config file
    config = {**config, **getFileConfig(config['config_file'])['Main']}
    
    # Validate config
    config = validateMainConfig(config)
    
    # Boto session
    session=getBotoSession(config)
    
    # Get EC2 and S3 clients from session
    ec2 = session.client('ec2')
    s3  = session.client('s3')
    # Retrieve VPN config from AWS
    awsVpn=ec2.describe_vpn_connections(VpnConnectionIds=[config['vpn_connection_id']])
        
    #Get XML 
    tree = ET.ElementTree(ET.fromstring(awsVpn['VpnConnections'][0]['CustomerGatewayConfiguration']))
    
    # Get the Customer gateway involve in this tunnel configuration from xml file
    config["customer_gateway_id"] = tree.find("customer_gateway_id").text
    
    # Adding configuration for the Customer Gateway from configuration file
    config = getCustomerGatewayIdConfig(config, getFileConfig(config['config_file']))
    
    # Establishing connection with the Customer Gateway
    sshClient = paramiko.SSHClient()    
    shell=getShell(config['hostname'], config['username'], config['password'],sshClient)
    
    # Send pre_config_commands.
    sshSendCommands(shell, config['pre_config_commands'], time_between_commands)
    logging.info('Dump output console: '+shell.recv(65535).decode('utf-8'))

    # Get current config
    sshSendCommands(shell, config['get_config_commands'], time_to_get_config)
    running_config = shell.recv(65535).decode('utf-8')
        
    # If we are provisioning a new VPN...
    if (config['delete'] is False):    
    
        # Find the vpn_connection_id string in the current configuration. If there is a match, maybe we are trying to redeploy the same config.
        # In this case, force=yes is required from command line.
        pattern = re.compile(config['vpn_connection_id'], re.UNICODE)
        if (pattern.search(running_config) is not None and not config['force']):
            logging.info('Looks like this configuration has been already applied... This string '
                         +config['vpn_connection_id']+' has been found in the configuration file')
            logging.info('Exiting...') 
            exit (-1)
        
        if config['create_template'].startswith('file:'):
            create_template = getLocalFile(config['create_template'].replace('file:',"",1)) 
        elif config['create_template'].startswith('s3:'):
            start = config['create_template'].index( 's3:' ) + len( 's3:' )
            end = config['create_template'].index( '/', start )
            create_template = getS3File( s3, config['create_template'][start:end], config['create_template'].replace('s3:'+config['create_template'][start:end]+'/',"",1))
        
        keys =  get_template_keys(create_template)
        replacements = getReplacementList(tree, keys, getFileConfig(config['config_file']), config, running_config)
        
        # Create create_config configuration based on create_config template
        create_config = create_configuration(create_template, replacements)
        
        if (config['delete_script']):
            # Create delete configuration based on delete template
            
            if config['delete_template'].startswith('file:'):
                delete_template = getLocalFile(config['delete_template'].replace('file:',"",1)) 
            elif config['delete_template'].startswith('s3:'):
                start = config['delete_template'].index( 's3:' ) + len( 's3:' )
                end = config['delete_template'].index( '/', start )
                delete_template = getS3File( s3, config['delete_template'][start:end], config['delete_template'].replace('s3:'+config['delete_template'][start:end]+'/',"",1))
            delete_config = create_configuration(delete_template, replacements)
        
        # Printing only
        if (config['dry_run'] ):
            logging.info('Dumping create_config config:\n' + create_config)
            
            if (config['delete_script']):
                logging.info('Dumping delete config:\n' + delete_config)
        
        # Applying config
        else:
            logging.info('Applying configuration...')
            logging.info('Dumping config:\n' + create_config)
            sshSendCommands(shell, create_config.splitlines(), time_between_commands)
            logging.info('Done')                           
            shell.recv(65535)
            sshSendCommands(shell, config['post_config_commands'], time_between_commands)
            logging.info('Dump output console: '+shell.recv(65535).decode('utf-8'))

            if(config['delete_script']):
                if config['delete_script_folder'].startswith('file:'):
                    putLocalFile( config['delete_script_folder'].replace('file:',"",1)+config['vpn_connection_id']+'.ftv',delete_config )
                     
                elif config['delete_script_folder'].startswith('s3:'):
                    start = config['delete_script_folder'].index( 's3:' ) + len( 's3:' )
                    end = config['delete_script_folder'].index( '/', start )
                    putS3File( s3, 
                               config['delete_script_folder'][start:end],
                               config['delete_script_folder'].replace('s3:'+config['delete_script_folder'][start:end]+'/',"",1)+config['vpn_connection_id']+'.ftv',
                    
                               delete_config)
                    
                
    # If we are deleting an existing config
    else:
        if config['delete_script_folder'].startswith('file:'):
            delete_config = getLocalFile( config['delete_script_folder'].replace('file:',"",1)+config['vpn_connection_id']+'.ftv')
             
        elif config['delete_script_folder'].startswith('s3:'):
            start = config['delete_script_folder'].index( 's3:' ) + len( 's3:' )
            end = config['delete_script_folder'].index( '/', start )
            delete_config = getS3File( s3, config['delete_script_folder'][start:end], 
                                       config['delete_script_folder'].replace('s3:'+config['delete_script_folder'][start:end]+'/',"",1)+config['vpn_connection_id']+'.ftv')

        # Only printing
        if (config['dry_run'] ):        
            logging.info('Dumping delete_config config:\n' + delete_config)
        #Apply config
        else:
            logging.info('Applying configuration...')
            logging.info('Dumping config:\n' + delete_config)
            sshSendCommands(shell, delete_config.splitlines(), time_between_commands)
            logging.info('Done')               
            shell.recv(65535)
            logging.info('Applying post config commands')
            sshSendCommands(shell, config['post_config_commands'], time_between_commands)
            logging.info('Dump output console: '+shell.recv(65535).decode('utf-8'))
            
    sshClient.close()
    logging.info('Finish!')
    
def addDefaultConfig():
    config = dict()
    config['log_level'] = 'error'
    config['aws_region'] = 'eu-west-1'
    config['aws_access_key_id'] = ''
    config['aws_secret_access_key'] = ''
    config['delete_script'] = True
    config['create_template'] = './generic_cisco_create.tmpl'
    config['delete_template'] = 'generic_cisco_delete.tmpl'
    config['config_file'] = './fawstvpn.cfg'
    config['vpn_connection_id'] = None
    config['dry_run'] = False
    config['force'] = False
    config['delete'] = False
    
    if os.name == 'nt': # Windows
        config['delete_script_folder'] = 'file:C:\windows\temp' # Untested
    else: # Unix like
        config['delete_script_folder'] = 'file:/tmp/'
    
    return(config)

def getCmdConfig():
    parser = argparse.ArgumentParser(description='Cisco configuration generator for AWS VPNs')
    parser.add_argument('--config_file', '-c', type=str, default='./fawstvpn.cfg', help="Configuration file. Default: ./fawstvpn.cfg")
    parser.add_argument('--vpn_connection_id', '-v', type=str, help="AWS VPN Connection ID.")
    parser.add_argument('--dry_run', '-d', action='store_true', help="Do not apply changes, just screen printing")
    parser.add_argument('--force', '-f', action='store_true', help="Force apply configuration")
    parser.add_argument('--delete', '-r', action='store_true', help="Remove an existing configuration instead of create a new one")
    
    return(vars(parser.parse_args()))

def getFileConfig(fileName):
    logging.debug('Trying configuration file %s.', fileName)
    fileConfig = configparser.ConfigParser()
    
    if (len(fileConfig.read(fileName)) != 1):
        logging.critical('Failed to open config file %s. Exiting.', fileName)
        exit(-1)
    
    if (not fileConfig.has_section('Main')):
        logging.critical('Main section do not found in config file %s. Exiting.', fileName)
        exit(-1)
    
    return (fileConfig)

def validateMainConfig(config):
    # Get configuration errors
    if (config['vpn_connection_id'] is None):
        logging.info('Fatal error, a AWS VPN Connection Id is mandatory')
        logging.info('Exiting...')
        exit(-1)
    else:
        logging.info("Running for VPN ID:" + config['vpn_connection_id'])
               
    try:
        config['delete_script'] = config.getboolean('Main','delete_script')
    except:
        config['delete_script']=False
    
    return(config)

def getLocalFile( filename ):
    f = open(filename, 'r')
    content = f.read()
    f.close()
    return ( content )

def putLocalFile( filename,content ):
    f = open(filename, 'w')
    f.write(content)
    f.close()
    return ( open(filename).read() )
        
def getS3File( s3, bucket, filename ):
    return( s3.get_object(Bucket=bucket, Key=filename)['Body'].read().decode('utf_8') )

def putS3File( s3, bucket, filename, content ):
    s3.put_object(Bucket=bucket, Key=filename,Body=content.encode('utf-8'))
    

def getBotoSession(config):
        if ( 'aws_access_key_id' in config and 'aws_secret_access_key' in config):
            session = boto3.session.Session(region_name=config['aws_region'], 
                                  aws_access_key_id=config['aws_access_key_id'], 
                                  aws_secret_access_key=config['aws_secret_access_key'])
        else:
            session = boto3.session.Session(region_name=config['aws_region'])
        return (session)
    
def find_free_conflict_number(conflicts,element):
    for i in range(0,1000):
        if (i == 1000):
            logging.info('There is not a free number for a conflict label')
            logging.info('Exiting')
            exit (-1)
        if i not in conflicts[element.replace("conflict-number:","",1)]:
            return(i)

def getShell(hostname,username,password,sshClient):
    try:
        sshClient.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        sshClient.connect(hostname=hostname,username=username,password=password, 
                          timeout=10,look_for_keys=False, allow_agent=False)
        sshClient.get_transport()
        return(sshClient.invoke_shell())

    except:
        logging.info('Could not connect with '+hostname)
        logging.info('Exiting...')
        exit (-1)

def sshSendCommand(sshClientShell, command, guard_time):
    sshClientShell.send(command+'\n')
    time.sleep(guard_time)

def sshSendCommands(sshClientShell, commands, guard_time):
    for command in commands:
        sshSendCommand(sshClientShell,command, guard_time)


def getCustomerGatewayIdConfig(config, fileConfig):
    if (not fileConfig.has_section(config["customer_gateway_id"])):
        logging.critical(config["customer_gateway_id"]+' section do not found in config file %s. Exiting.', filename)
        exit(-1)

    # Default config
    config['hostname'] = 'localhost'
    config['username'] = 'admin'
    config['password'] = 'password'
    config['get_config_commands'] = "terminal length 0,show run"
    config['pre_config_commands'] = ""
    config['post_config_commands'] = ""
    
    # Get customer gateway configuration from file
    config.update(fileConfig[config["customer_gateway_id"]])
    
    # Prepare commands
    config['get_config_commands'] = config['get_config_commands'].split(',')
    config['pre_config_commands'] = config['pre_config_commands'].split(',')
    config['post_config_commands'] = config['post_config_commands'].split(',')
    
    try:
        config['delete_script'] = fileConfig.getboolean(config["customer_gateway_id"],'delete_script')
    except ValueError:
        config['delete_script']=False

    return(config)


def get_template_keys(template): 
    keys = list()
        
    pattern = re.compile(r'\{(.+?)\}', re.UNICODE)
    for match in pattern.findall(template):
        keys.append(match)
        
    return( set(keys) )

def getReplacementList(tree, unique_keys, fileConfig, config, running_config):
    conflicts = dict()
    replacement = list()
    repetition = 0
    tunnel_list = tree.findall("ipsec_tunnel")
    
    # Each ipsec_tunnel in the XML file needs a router configuration.      
    for tunnel in tunnel_list:
        bilist = dict()
        # We must check all the keys in the configuration file
        for element in unique_keys:
            # If the template key begins with xml:, find the replacement value in the xml from AWS API
            if (element.startswith("xml:")):
                key = tunnel.find(element.replace("xml:","",1))
                
                if (key is None):
                    logging.info('Fatal error: '+element+' is not in XML')
                    exit (-1)
                
                bilist[element]=key.text
            # If the template key begins with config:, find the replacement value in Customer Gateway section in the config file
            elif (element.startswith("config:")):
                try:                    
                    bilist[element]=fileConfig.get(config["customer_gateway_id"], element.replace("config:","",1)).lower()
                except (configparser.NoSectionError):
                    logging.info('Section \"'+config["customer_gateway_id"]+'\" not found in config file')
                    exit (-1)
                except (configparser.NoOptionError):
                    logging.info('Configuration parameter '+element.replace("config:","",1).lower()+' not found in config file')
                    exit (-1)
            # If the template key is the VPN Connection Id, replace it
            elif (element == "vpn_connection_id"):
                bilist[element]=config['vpn_connection_id']
            # If the template key is the repetition, replace with the repetition variable.
            elif (element == "repetition"):
                bilist[element]=repetition
            # If the template key begins with conflict-number...
            elif (element.startswith("conflict-number:")):
                # If the string after "conflict-number:" tag already exist in the conflicts dictionary, it's not the first conflict match in the XML
                # So, we can find a free number in the conflicts dictionary for the replacement 
                if (element.replace("conflict-number:","",1) in conflicts):
                    bilist[element]=find_free_conflict_number(conflicts,element)
                    conflicts[element.replace("conflict-number:","",1)].add(bilist[element])
                                             
                # If it is not in the dictionary...
                else:
                    # Create a new set for that key in the dictionary
                    conflicts[element.replace("conflict-number:","",1)] = set()
    
                    # Get all the numbers after the key definition, for example, conflict-number: interface Tunnel, and all of of them
                    # to the conflicts dictionary
                    pattern = re.compile(element.replace("conflict-number:","",1)+'(.+)', re.UNICODE)
                    
                    for match in pattern.findall(running_config):
                        conflicts[element.replace("conflict-number:","",1)].add(int(match))
                        
                    # And now we can find a free number in the dictionary
                    bilist[element]=find_free_conflict_number(conflicts,element)
                    conflicts[element.replace("conflict-number:","",1)].add(bilist[element])
    
        repetition = repetition + 1
        replacement.append(bilist)
        
    return(replacement)

def create_configuration(template, replacement_list):

    output = str()
    for replacement in replacement_list:
        for line in template.splitlines():
            for src, target in replacement.items():
                line = line.replace("{"+str(src)+"}", str(target))
            output+=line+("\n")
    return(output)

if __name__ == '__main__':
    main()
