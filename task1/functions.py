from datetime import timezone
from dateutil import parser
import csv

import unittest


def read_and_transform_txt(file_path):
    with open(file_path, newline='') as txtfile:
        reader = csv.reader(txtfile, delimiter=',')
        dictionaries_list=[]
        key_list = ["datetime", "source_ip", "destination_ip", "port", "event_type", "priority"]

        for row in reader:
            
            dictionaries_list.append(dict(zip(key_list, row)))
          
            
    return dictionaries_list
            


def transform_date(dictionaries_list):
    
    for element in dictionaries_list:
        element['datetime'] = parser.parse(element['datetime']).astimezone(timezone.utc).replace(tzinfo=None).strftime("%Y-%m-%d %H:%M:%S")       
        
    return dictionaries_list


def add_security_level(dictionaries_list):
    threat_low = ["1" , "2"]
    threat_medium = ["3", "4"]
    threat_high = ["5"]

    for element in dictionaries_list:
        priority = element['priority']
        match priority: 
            case priority if priority in threat_low: 
                element.update(dict({'threat_level':'Low'}))
            case priority if priority in threat_medium: 
                element.update(dict({'threat_level':'Medium'}))
            case priority if priority in threat_high: 
                element.update(dict({'threat_level':'High'}))
            case _:
                element.update(dict({'threat_level':'Undefined'}))
    return dictionaries_list
    

def main():
    list_of_events = add_security_level(transform_date(read_and_transform_txt("./task1/events_siem.txt")))
    print(list_of_events)


        







