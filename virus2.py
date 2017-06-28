#-*- coding: utf-8 -*-
import requests
import postfile
import ast
import xlwt
import os
import tkFileDialog
import time
from time import localtime,strftime





VT_KEY     = 'b201122cd29fe5b21f6244f08f7c69c3ceda72dce2842a88936c461f74dd9c4c'
HOST       = 'www.virustotal.com'
SCAN_URL   = 'https://www.virustotal.com/vtapi/v2/file/scan'
REPORT_URL = 'https://www.virustotal.com/vtapi/v2/file/report'
fields = [('apikey', VT_KEY)]

folder = tkFileDialog.askdirectory()
print "Selected Folder:", folder

def search(dirname):
    filenames = os.listdir(dirname)

    workbook = xlwt.Workbook()
    t=1
    for filename in filenames:
        t=t+1
        full_filename = os.path.join(dirname, filename)
        k=unicode(full_filename)
        filepath = k
        ext = os.path.splitext(full_filename)[-1]
        file_to_send = open(filepath.encode('cp949'), 'rb').read()
        files = [('file', filepath.encode('cp949'), file_to_send)]
        q=filepath.find("\\")
        print full_filename




        data = postfile.post_multipart(HOST, SCAN_URL, fields, files)
        data = ast.literal_eval(data)
        resource = data['resource']


        params = {'apikey': VT_KEY, 'resource': resource}
        headers = {
          "Accept-Encoding": "gzip, deflate",
          "User-Agent": "gzip,  My Python requests library example client or username"
        }


        response = requests.get('https://www.virustotal.com/vtapi/v2/file/report',
                                params=params, headers=headers)
        json_response = response.json()
        time.sleep(15)



        workbook.default_style.font.heignt = 20 * 11
        xlwt.add_palette_colour("lightgray", 0x21)
        workbook.set_colour_RGB(0x21, 216, 216, 216)
        xlwt.add_palette_colour("lightgreen", 0x22)
        workbook.set_colour_RGB(0x22, 216, 228, 188)

        worksheet = workbook.add_sheet(filepath[q+1:])
        col_width_1 = 256 * 30
        col_width_2 = 256 * 21
        col_width_3 = 256 * 13


        worksheet.col(0).width = col_width_3
        worksheet.col(1).width = col_width_2
        worksheet.col(2).width = col_width_2
        worksheet.col(3).width = col_width_1


        list_style = "font:height 180,bold on; pattern: pattern solid, fore_color lightgray; align: wrap on, vert centre, horiz center"

        worksheet.write_merge(0, 0, 0, 3, full_filename, xlwt.easyxf(list_style))
        worksheet.write(1, 0, "sha256", xlwt.easyxf(list_style))
        worksheet.write_merge(1, 1, 1, 3, json_response['sha256'])
        worksheet.write(2, 0, "Vaccine", xlwt.easyxf(list_style))
        worksheet.write(2, 1, "Version", xlwt.easyxf(list_style))
        worksheet.write(2, 2, "Update", xlwt.easyxf(list_style))
        worksheet.write(2, 3, "Detect", xlwt.easyxf(list_style))
        i=3
        for h in json_response['scans']:
            type = str(h)

            worksheet.write(i,0,h)
            worksheet.write(i,1,json_response['scans'][str(type)]['version'])
            worksheet.write(i,2,json_response['scans'][str(type)]['update'])
            if str(json_response['scans'][str(type)]['detected'])=='True':
                worksheet.write(i,3,json_response['scans'][str(type)]['result'])
            else:
                worksheet.write(i,3,json_response['scans'][str(type)]['detected'])
            i=i+1
    workbook.save(str(strftime("%y-%m-%d_%H(h)_%M(m)_%S(s).xls",localtime())))

search(folder)


