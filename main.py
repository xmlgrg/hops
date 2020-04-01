#!/usr/bin/env python
# -*- coding:utf-8 -*-
#########################################################################
# Author:Jeson
# Email:jeson@imoocc.com

import datetime
import os

import yaml

PROJECT_ROOT = os.path.realpath(os.path.dirname(__file__))
# import sys
os.environ["DJANGO_SETTINGS_MODULE"] = 'admin.settings.local_cj'
import django

django.setup()
from scanhosts.util.nmap_all_server import NmapDocker
from scanhosts.util.nmap_all_server import NmapKVM
from scanhosts.util.nmap_all_server import NmapVMX
from scanhosts.util.j_filter import FilterRules
from scanhosts.util.get_pv_relation import GetHostType
from detail.models import PhysicalServerInfo

import logging

logger = logging.getLogger("django")


def main():
    """
    读取扫描所需配置文件
    :return:
    """
    with open('conf/scanhosts.yaml') as f:
        s_conf = yaml.load(f, Loader=yaml.FullLoader)
        s_nets = s_conf['hostsinfo']['nets']
        s_ports = s_conf['hostsinfo']['ports']
        s_pass = s_conf['hostsinfo']['ssh_pass']
        s_cmds = s_conf['hostsinfo']['syscmd_list']
        s_keys = s_conf['hostsinfo']['ssh_key_file']
        s_blacks = s_conf['hostsinfo']['black_list']
        s_emails = s_conf['hostsinfo']['email_list']

        n_sysname_oid = s_conf['netinfo']['sysname_oid']
        n_sn_oid = s_conf['netinfo']['sn_oids']
        n_commu = s_conf['netinfo']['community']
        n_login_sw = s_conf['netinfo']['login_enable']
        n_backup_sw = s_conf['netinfo']['backup_enable']
        n_backup_sever = s_conf['netinfo']['tfp_server']

        d_pass = s_conf['dockerinfo']['ssh_pass']
        starttime = datetime.datetime.now()

        '''
        规则：主机信息，去重、生成关系字典
        '''
        ft = FilterRules()
        key_ip_dic = ft.run()

        '''
        梳理虚拟服务器主机于服务器信息
        '''
        pv = GetHostType()
        p_relate_dic = pv.get_host_type(key_ip_dic)

        '''
        更新宿主机类型中表对应关系
        '''
        ip_key_dic = {v: k for k, v in key_ip_dic.items()}
        docker_p_list = p_relate_dic["docker-containerd"]
        kvm_p_list = p_relate_dic["qemu-system-x86_64"]
        vmware_p_list = p_relate_dic["vmx"]
        for item in docker_p_list:
            PhysicalServerInfo.objects.filter(conn_phy__sn_key=ip_key_dic[item]).update(vir_type="1")
        for item in kvm_p_list:
            PhysicalServerInfo.objects.filter(conn_phy__sn_key=ip_key_dic[item]).update(vir_type="0")
        for item in vmware_p_list:
            PhysicalServerInfo.objects.filter(conn_phy__sn_key=ip_key_dic[item]).update(vir_type="2")

        '''
        扫描docker的宿主机和虚拟服务的关系
        '''
        ds = NmapDocker(s_cmds, d_pass, ip_key_dic)
        ds.do_nmap(docker_p_list)
        #
        # '''
        # 扫描KVM的宿主机和虚拟服务的关系
        # '''
        ks = NmapKVM(ip_key_dic)
        ks.do_nmap(kvm_p_list)

        '''
        扫描ESXI虚拟机配置
        '''
        ne = NmapVMX(vmware_p_list, ip_key_dic)
        ne.dosnmp()

        endtime = datetime.datetime.now()
        totaltime = (endtime - starttime).seconds

        logger.info("{Finish:Use time %s s}" % totaltime)
        print("{Finish:Use time %s s}" % totaltime)


if __name__ == "__main__":
    main()
