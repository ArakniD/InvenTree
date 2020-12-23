# -*- coding: utf-8 -*-

"""
DigiKey barcode decoding
"""

import http.client
import json
import requests
import re
import os
import time
import urllib
import common.models

from barcode.barcode import BarcodePlugin

from stock.models import StockItem, StockLocation
from part.models import Part
from stock import models as StockModels
from company.models import Company, SupplierPart

from rest_framework.exceptions import ValidationError

DEFAULT_API_URL = "api.digikey.com"

known_dis = {
    "K": "Customer PO Number",
    "1K": "Supplier Order Number",
    "10K": "Invoice Number",
    "P": "Part No.",
    "1P": "Supplier Part Number",
    "Q": "Quantity",
    "4L": "Country of Origin",
}

class DigikeyBarcodePlugin(BarcodePlugin):

    PLUGIN_NAME = "DigikeyBarcode"

    def __init__(self, barcode_data):
        """
        Initialize the BarcodePlugin instance

        Args:
            barcode_data - The raw barcode data
        """
        self.data = barcode_data
        self.client_id = ""
        self.access_token = ""
        self.refresh_token = ""
        self.token_expiration = 0
        self.fields = None
        self.barcode = ""
        self.client_secret = ""
        self.api_url = DEFAULT_API_URL
        self.valid = False
        self.debug = True
        self.rs_str = "\x1e"
        self.gs_str = "\x1d"
        self.eot_str = "\x04"
        self.part_data = None
        self.barcode_data = None
        self.scan_barcode = ""
        self.salesorder_id = None
        self.invoice_id = None
        self.purchase_order = None
        self.batch_id = ""
        self.quantity = 0
        self.__update_config()
        
    def __update_config(self):
        self.client_id = common.models.InvenTreeSetting.get_setting("DIGIKEY_CLIENT_ID")
        self.access_token = common.models.InvenTreeSetting.get_setting("DIGIKEY_ACCESS_TOKEN")
        self.refresh_token = common.models.InvenTreeSetting.get_setting("DIGIKEY_REFRESH_TOKEN")
        self.token_expiration = common.models.InvenTreeSetting.get_setting("DIGIKEY_TOKEN_EXPIRATION")
        self.client_secret = common.models.InvenTreeSetting.get_setting("DIGIKEY_CLIENT_SECRET")
        
        if common.models.InvenTreeSetting.get_setting_default("DIGIKEY_ACCESS_TOKEN") != self.access_token:
            self.valid = True

            if int(self.token_expiration) < time.time():
                self.__refresh_token()

        return self.valid

    def __refresh_token(self):
        # https://api-portal.digikey.com/app_overview

        post_request = {
            "refresh_token": self.refresh_token,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "grant_type": "refresh_token",
        }

        # code  The authorization code returned from the initial request (See above example).
        # client_id This is the client id assigned to the application that you generated within the API Portal.
        # client_secret This is the client secret assigned to the application that you generated within the API Portal.
        # redirect_uri  This URI must match the redirect URI that you defined while creating your application within the API Portal.
        # grant_type    As defined in the OAuth 2.0 specification, this field must contain a value of authorization_code.

        request_url = "https://" + self.api_url + "/v1/oauth2/token"

        r = requests.post(request_url, data=post_request)
        response = r.json()

        if self.debug:
            print("Making request to")
            print(r.status_code)
            print(response)

        if r.status_code == 200:
            self.refresh_token = response["refresh_token"]
            self.access_token = response["access_token"]
            self.token_expiration = int(time.time()) + int(
                response["expires_in"]
            )
            
            # Store the new tokens in settings please
            common.models.InvenTreeSetting.set_setting_force("DIGIKEY_ACCESS_TOKEN", self.access_token )
            common.models.InvenTreeSetting.set_setting_force("DIGIKEY_REFRESH_TOKEN", self.refresh_token)
            common.models.InvenTreeSetting.set_setting_force("DIGIKEY_TOKEN_EXPIRATION", self.token_expiration)
            
        elif self.debug:
            print("ERROR")

    def process_barcode(self, barcode):
        barcode_1d_re = re.compile("^[0-9]+$")

        if barcode_1d_re.match(barcode):
            return self.process_1d_barcode(barcode)
        else:
            return self.process_2d_barcode(barcode)

    def process_1d_barcode(self, barcode):
        self.__update_config()

        conn = http.client.HTTPSConnection(self.api_url)

        headers = {
            "x-DIGIKEY-client-id": self.client_id,
            "authorization": "Bearer " + self.access_token,
            "content-type": "application/json",
            "accept": "application/json",
        }

        conn.request(
            "GET",
            "/Barcoding/v3/ProductBarcodes/" + urllib.parse.quote(barcode),
            None,
            headers,
        )

        res = conn.getresponse()
        data = json.loads(res.read())

        if "httpMessage" in data and data["httpMessage"] == "Unauthorized":
            if self.debug:
                print("Unauthorized! Need to refresh token.")
            return None
        else:
            return data

    def process_2d_barcode(self, barcode):
        self.__update_config()

        conn = http.client.HTTPSConnection(self.api_url)

        headers = {
            "x-DIGIKEY-client-id": self.client_id,
            "authorization": "Bearer " + self.access_token,
            "content-type": "application/json",
            "accept": "application/json",
        }

        conn.request(
            "GET",
            "/Barcoding/v3/Product2DBarcodes/" + urllib.parse.quote(barcode, safe=''),
            None,
            headers,
        )

        res = conn.getresponse()
        data = json.loads(res.read())

        if "httpMessage" in data and data["httpMessage"] == "Unauthorized":
            if self.debug:
                print("Unauthorized! Need to refresh token.")
            return None
        else:
            return data

    def decode_2d_barcode(self, barcode):
        iso_iec_15434_start = re.compile(
            "^>?\[\)>({})?[>]?[0-9]{{2}}{}".format(self.rs_str, self.gs_str)
        )

        # https://www.eurodatacouncil.org/images/documents/ANS_MH10.8.2%20_CM_20140512.pdf
        ansi_mh10_8_2_item = re.compile("(?P<DI>[0-9]*[A-Z])(?P<value>[A-Za-z0-9\-\.\ ]*)")

        # Check for valid code first
        if not iso_iec_15434_start.match(barcode):
            raise ValueError({barcode, "Not an ISO IEC 15434 Code"})

        self.fields = {}
        sections = barcode.split(self.gs_str)
        for section in sections[1:]:
            match = ansi_mh10_8_2_item.match(section)
            if match:
                di = match.group("DI")
                value = match.group("value")

                if di in known_dis:
                    self.fields[known_dis[di]] = value
                elif self.debug:
                    print("NEW DI!", di, value)
            elif self.debug:
                print("Invalid section", section)

        return self.fields

    def get_part_details(self, part_no):
        self.__update_config()

        conn = http.client.HTTPSConnection(self.api_url)

        # TODO - escape part_no quotes
        payload = '{"Keywords": "' + part_no + '","RecordCount": "50"}'

        headers = {
            "x-DIGIKEY-client-id": self.client_id,
            "authorization": "Bearer " + self.access_token,
            "content-type": "application/json",
            "accept": "application/json",
        }

        conn.request(
            "POST", "/Search/v3/Products/Keyword", payload.encode("utf-8"), headers
        )

        res = conn.getresponse()

        data = json.loads(res.read().decode("utf-8"))

        if "httpMessage" in data and data["httpMessage"] == "Unauthorized":
            if self.debug:
                print("Unauthorized! Need to refresh token.")
            return None
        else:
            return data
        
    def validate(self):
        """
        An "DigiKey" barcode must be a jsonnable-dict with the following tags:

        {
            'barcode': '1D/2D DigiKey barcode',
            'partnumber': '2ND-3303003-3-ND',
        }

        """
        # If any of the following keys are in the JSON data,
        # let's go ahead and assume that the code is a valid InvenTree one...
        barcode_data = None

        if type(self.data) is dict and 'partnumber' in self.data:
            self.part_data = self.get_part_details(self.data['partnumber'])

            if self.part_data is None:
                return False

            self.manu_number=part_data["ManufacturerPartNumber"]
            self.part_number=part_data["DigiKeyPartNumber"]
            
        else:
            if type(self.data) is dict and 'barcode' in self.data:
                barcode = self.data['barcode']
            elif type(self.data) is str:
                barcode = self.data
            else:
                raise ValidationError({self.data: "Unknown input"})

            self.scan_barcode = barcode

            try:
               
                # Try to decode barcode to see if it's a valid 2d barcode
                fields = self.decode_2d_barcode(barcode)

                self.purchase_order = fields["Customer PO Number"]
                self.salesorder_id = fields["Supplier Order Number"]
                self.invoice_id = fields["Invoice Number"]
                self.part_number = fields["Part No."]
                self.manu_number = fields["Supplier Part Number"]
                self.quantity = int(fields["Quantity"])
                self.batch_id = f'{self.salesorder_id}' + "-" + f'{self.invoice_id}'

            except (ValueError, KeyError):
                try:
                    self.barcode_data = self.process_barcode(barcode)

                    if self.barcode_data is None:
                        raise ValidationError({self.scan_barcode: "Return data is none-dict"})

                    if self.debug:
                        print(self.barcode_data)

                    new_code = [
                        "[)>\x1e06",
                        "1P" + self.barcode_data["ManufacturerPartNumber"],
                        "P" + self.barcode_data["DigiKeyPartNumber"],
                    ]

                    # Add GS delimiters and EOT at the end
                    self.part_barcode = "\x1d".join(new_code) + "\x04"
                    self.part_number = self.barcode_data["DigiKeyPartNumber"]
                    self.manu_number = self.barcode_data["ManufacturerPartNumber"]
                    self.salesorder_id = int(self.barcode_data["SalesorderId"])
                    self.invoice_id = int(self.barcode_data["InvoiceId"])
                    self.purchase_order = self.barcode_data["PurchaseOrder"]
                    self.batch_id = f'{self.salesorder_id}' + "-" + f'{self.invoice_id}'
                    self.quantity = int(self.barcode_data["Quantity"])

                except (ValueError, KeyError):
                    raise ValidationError({self.scan_barcode: "Error processing barcode"})

        return True

    def getStockItem(self):
        part_number_none = False
        company = None

        if self.batch_id is None:
            return None
        
        if self.debug:
            print("Getting Stock Info")

        try:
            if self.part_number is not None:
                try:
                    supplier_part = SupplierPart.objects.get(SKU=self.part_number)
                    return StockModels.StockItem.objects.get(part=supplier_part.part,batch=self.batch_id)
                except (ValueError, SupplierPart.DoesNotExist):
                    part_number_none = True
                   
            if not self.manu_number is None:
                try:
                    company = Company.objects.get(name="DigiKey")
                except (ValueError, Company.DoesNotExist):
                    if self.debug:
                        print("No Company Found")
                    return None
                try:
                    supplier_part = SupplierPart.objects.get(MPN=self.manu_number,supplier=company)
                    return StockModels.StockItem.objects.get(part=supplier_part.part,batch=self.batch_id)
                except (ValueError, SupplierPart.DoesNotExist):
                    if self.debug:
                        print('ManufacturerPartNumber does not exist')
                    return None

        except (ValueError, StockItem.DoesNotExist):
            print("Stock item does not exist")
            
        if part_number_none:
            print('Supplier Part Number does not exist')

        return None

    def addStockItem(self,request):
        company = None
        supplierPart = None
        stock = None
        try:
            company = Company.objects.get(name="DigiKey")
        except (ValueError, Company.DoesNotExist):
            if self.debug:
                print("No Company Found")
            return None
    
     # Try get SupplierPart before create SupplierPart
        try:
            supplierPart = SupplierPart.objects.get(MPN=self.manu_number)
        except (ValueError, SupplierPart.DoesNotExist):
            return None

        if self.quantity <= 0 or self.batch_id == '':
            return None

        try:
            stock = StockModels.StockItem.objects.get(part=supplierPart.part,batch=self.batch_id)
        except (ValueError, StockItem.DoesNotExist):
            stock = StockModels.StockItem.objects.create(
                part = supplierPart.part,
                supplier_part = supplierPart,
                batch = self.batch_id,
                quantity = self.quantity,
            )
            stock.save(user=request)

        return stock

    def getStockLocation(self):
        part_number_none = False
        supplier_part = None
        company = None
        
        try:
            company = Company.objects.get(name="DigiKey")
        except (ValueError, Company.DoesNotExist):
            if self.debug:
                print("No Company Found")
            return None
        
        if not self.part_number is None:
            try:
                supplier_part = SupplierPart.objects.get(SKU=self.part_number)
            except (ValueError, SupplierPart.DoesNotExist):
                part_number_none = True
               
        if not self.manu_number is None:
            try:
                supplier_part = SupplierPart.objects.get(MPN=self.manu_number,supplier=company)
            except (ValueError, SupplierPart.DoesNotExist):
                if self.debug:
                    print("ManufacturerPartNumber does not exist")

        if supplier_part is not None and supplier_part.part.default_location is not None:
            try:
                location = StockLocation.objects.get(pk=supplier_part.part.default_location.id)
                return location
            except StockLocation.DoesNotExist:
                if self.debug:
                    print('StockLocation does not exist')

        return None

    def addPart(self,request):
        company = None
        manufacturer = None
        part = None
        newPart = False

        if self.debug:
            print("Adding Part")

        try:
            company = Company.objects.get(name="DigiKey")
        except (ValueError, Company.DoesNotExist):
            if self.debug:
                print("No Company Found")
            return None
    
        if self.part_number is not None and self.manu_number is not None:
            # Try get Part before Create Part
            try:
                part = Part.objects.get(name=self.manu_number)
            except (ValueError, Part.DoesNotExist):
                newPart = True

                if self.part_data is None:
                    self.part_data = self.get_part_details(self.part_number)

                part = Part.objects.create(
                    name=self.manu_number,
                    description=self.part_data["DetailedDescription"],
                    component=True,
                    purchaseable=True,
                    trackable=False,
                    active=True,
                    virtual=False,
                    link=self.part_data["PrimaryDatasheet"]
                )
                part.save() #user=request)
            
            # Try get SupplierPart before create SupplierPart
            try:
                supplierPart = SupplierPart.objects.get(MPN=self.manu_number)
            except (ValueError, SupplierPart.DoesNotExist):
                try:
                    if self.part_data is None:
                        self.part_data = self.get_part_details(self.part_number)

                    manufacturer = Company.objects.get(name=self.part_data["Manufacturer"]["Value"])
                except KeyError:
                    if self.debug:
                        print("Error in digikey data?")
                except (ValueError, Company.DoesNotExist):
                    manufacturer = Company.objects.create( 
                        name=self.part_data["Manufacturer"]["Value"],
                        is_customer = False,
                        is_supplier = False,
                        is_manufacturer = True
                    )
                    manufacturer.save() #user=request)

                supplierPart = SupplierPart.objects.create(
                    part = part,
                    SKU = self.part_number,
                    MPN = self.manu_number,
                    supplier = company,
                    manufacturer = manufacturer,
                    link = self.part_data["ProductUrl"]
                )
                supplierPart.save() #user=request)
            
            if newPart:
                part.default_supplier = supplierPart
                part.save()

        return part

    def getPart(self):
        part_number_none = False
        company = None
        part = None

        try:
            company = Company.objects.get(name="DigiKey")
        except (ValueError, Company.DoesNotExist):
            if self.debug:
                print("No Company Found")
            return None
            
        if not self.part_number is None:
            try:
                supplier_part = SupplierPart.objects.get(SKU=self.part_number)
                return supplier_part.part
            except (ValueError, SupplierPart.DoesNotExist):
                part_number_none = True
               
        if not self.manu_number is None:
            try:
                supplier_part = SupplierPart.objects.get(MPN=self.manu_number,supplier=company)
                return supplier_part.part
            except (ValueError, SupplierPart.DoesNotExist):
                if self.debug:
                    print('ManufacturerPartNumber does not exist')

        if part_number_none and self.debug:
            print('Supplier Part Number does not exist')

        return None
