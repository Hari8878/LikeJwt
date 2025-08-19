# Code by @xp_owner99 | Don’t upload without credit 

from flask import Flask, request, jsonify
import asyncio
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.json_format import MessageToJson
import binascii
import aiohttp
import requests
import json
import like_pb2
import like_count_pb2
import uid_generator_pb2
import my_pb2
import output_pb2
import time
from collections import defaultdict
from datetime import datetime

import urllib3
# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


from concurrent.futures import ThreadPoolExecutor, as_completed
app = Flask(__name__)
AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV = b'6oyZDr22E3ychjM%'
# ✅ Per-key rate limit setup
KEY_LIMIT = 150
token_tracker = defaultdict(lambda: [0, time.time()])  # token: [count, last_reset_time]

def get_today_midnight_timestamp():
    now = datetime.now()
    midnight = datetime(now.year, now.month, now.day)
    return midnight.timestamp()

def load_tokens(server_name):
    if server_name == "IND":
        with open("token_ind.json", "r") as f:
            return json.load(f)
    elif server_name in {"BR", "US", "SAC", "NA"}:
        with open("token_br.json", "r") as f:
            return json.load(f)
    else:
        with open("token_bd.json", "r") as f:
            return json.load(f)

def load_tokens_backup():
    return [ (
    "3809672440",
    "829259A4F0538B5EC35470E09BA1608E6AA4B0E5D62EDFE7428E29D3D95E264E"
) , (
    "3810394871",
    "B2AC8F77A1D0EDFC5966D8C813964FB5DE23ECDEA2DC415C7630A7695936138A"
) , (
    "3810396318",
    "E8437EC62512E759AE6220FDBD5B4354799BC8276EADAAD8437D61CB61E07E8B"
) , (
    "3810399947",
    "08DA9EA26A213F7AEDFECD2EF751C835F9F6FF315306D0040461FA4A78286F1B"
) , (
    "3810403736",
    "0580F3359BC5A1D68BC3496D7CA27C7465F871CBF3F50796A5E60F8E9B2C92E1"
) , (
    "3810406203",
    "4E5330DEC30D6FB5C053FA01A9DE02E1809822AADE6AA76BDC7B09B36A515897"
) , (
    "3810445141",
    "A75A5058B54CA20B4B176B261D7FB6652335FDD09CA77BB23DD1C6131E9DD763"
) , (
    "3810448538",
    "134375CF91B5A7F155E2ED5AA83605704E248D24E6B50D2A79DC89F5C629F753"
) , (
    "3810449689",
    "44B01F960415EC4E3B9D7B676CBBC38B13008D0981A95B3D3A2681E40F9A68C1"
) , (
    "3810452612",
    "2EEDE835F6B501190632E559E14155E93177BF2D44D170744EFD9CA993B344F7"
) , (
    "3810454059",
    "5A41230ECD9347078ECA0FC4FC126FF07BAE070400F1743C36ED688FCB074920"
) , (
    "3810456594",
    "1DF429525755A438124C75ED1B291C93A5BD19E2DA716FC9D32153D2E2499D81"
) , (
    "3810466547",
    "24D604D9EE6E0E2EFFA9BED3A68205373F0E300FC944D76AFB507D16F1CB5B49"
) , (
    "3810467661",
    "BF5B009A6840CFD4F6A7281D8EC0A4204DEF56F0FFEF26864B266B6877DFF706"
) , (
    "3810468807",
    "0E171EED6A84A251D41CAF5038590AE9285B3F74B595338C9FC04BAF2CE5A1F6"
) , (
    "3810469789",
    "4B6927F36B2B2F5A0B791E10FE17BAFBFCCB598547F8C30E265E9039C63DEE79"
) , (
    "3810470843",
    "EB34DB14BABEEB3FF229B2E636D5152F70C953E2788CD1CAE1E0238B66DDE2B1"
) , (
    "3810471853",
    "6E7C8C8D358416BDD38465D1FF09A69F7C21F968FEB4F9C5BB30C3424EE1E79F"
) , (
    "3810473242",
    "3DE928BF13D4435447E069BA5D0D50A4A00F214358345E3B2BB0827DBEB5B864"
),
 (
    "3810474307",
    "4752E57DFB557638561AEC7A0488FE3A8395EE643BAF0FA549B8328EEAC4D357"
) , (
    "3810489354",
    "6340525911F2F249217A6997D0F83520B02683525D2CE2B7CF9D03B801E045B1"
) , (
    "3810491062",
    "5D481BA76B81CE128E37BDEF393AFB0F2F49B6B010CBE02636884D13870E4307"
) , (
    "3810492023",
    "B164D7450B8BE5E3CFBA40B1409BBCD37A69EB8C941297A76BF4AECB04899FEF"
) , (
    "3810493146",
    "DE2D4019AC1AA7E9535F9531E45E1CF2EF5FF1269386F340094776DF5893B72B"
) , (
    "3810494182",
    "25BBDD518796F51C1074C04831520C0098EAB7668DC332FCFAF434E3B962E087"
) , (
    "3810495323",
    "D3DC7BF46BF963109F06B93DEBF859E4BA2D3D81E3D49B0963153CB515C7D8ED"
) , (
    "3810497170",
    "FCBB0624FB4DDF1A8B43AC0403F2512F76A9B794EBE669C7E1096C56F701FAA2"
) , (
    "3810498243",
    "BA51A8E4C4692D1BD56CFE9C58AACA0F7EC8BC88E8AFDA323DE107F6779E8BD1"
) , (
    "3810499307",
    "8D12654A7EB529DC5B64C65BCE440F409ECC1DBECBB8C4FE69B5C228BBFBDAB8"
) , (
    "3810500419",
    "F5B7695797A166CD41E2381A1D42E9E850239AE62DD8E3FCCD231F27681BD5F3"
) , (
    "3810508495",
    "6020C12E10867308B08E6A1337F46C3FC4EB6AD345FF3E37D62E024DDB448B6C"
) , (
    "3810518518",
    "0BFDB977853407AF10A52B9AE87FC3918BF81CB2136F4CCB2B640CCA9AE2B60A"
) , (
    "3810520357",
    "B165A5327D4807043D6F42725805B0D4962D12688A9FD0FD5D77EB98F54A9147"
) , (
    "3810522368",
    "F536F2F7ECE0FD300EDD12183923B1D74C1CD4F082C52A137BB8E05B05DF0D76"
) , (
    "3810523376",
    "95196003135EAC2FD755E82431EF937E594F461BF3F3DB13C0036AC38AA1CBE6"
) , (
    "3810524346",
    "F340CB69D5D06DBEC8933DD7B041B042CCC1B0748909E857F9FEEA166D1B8C91"
) , (
    "3810543668",
    "48F6F4E0FA04AC4CFD96598A572A8BA414DD704AA015A6863BF6994DD94BB845"
) , (
    "3810545564",
    "3F304F4853693D973D1C7023C2F5D2671113535F7B1101112DA8EE559586837E"
) , (
    "3810546543",
    "9C820DE12649EF7A1249FAB919B71FFADB21019DC08E350D7A2DD6A912ECFDFF"
) , (
    "3810549850",
    "9EA1A9343A508FED1B1E3AE7334C0B4C342B1AD59319E8B1260A5C833C75E513"
) , (
    "3810615267",
    "D0310F57D18A5F8CC18CCF9246A81B218FDE346889A89A907236025CDC1FD752"
) , (
    "3810618272",
    "DA284FD6741F066A8D78DA14966EC7549AF1EEBC92BF56A515A6DCB5A9F05FFD"
) , (
    "3810619358",
    "AC7EA8D9C7B070BFA6F501F86F1EAEBB5242E4196F54E299E0A57B7C06CED37D"
) , (
    "3810620228",
    "B3BDF0C4765EAC2BA7D53DA374C0FE9C3BAA1C52B565DF6E2D9B5EEF23D9F37A"
) , (
    "3810621423",
    "FD872DE64E27A949C9F7DC6DA239953223D1A3201D19D8AE71F323A6706951F4"
) , (
    "3810676173",
    "D2AA4E2BD0A91A5BA015C9D7774C6B2358021246533ADA3A53D1B2D928412A71"
) , (
    "3810677302",
    "B17545050BF26B204B71A44603C8167F9777B56E0EF5D7FE4B51E4E9E7CAA8DF"
) , (
    "3810678538",
    "FF744E7C1BFB1FF7E53F5EF16768321E0F265686FA4D4538077F8EDF48AD73A4"
) , (
    "3810679688",
    "98090C09733472E02FC2B7E381DA6C6C9D4D66ED6652E2C37702F4CD2BA4A5C2"
) , (
    "3810680784",
    "16E800804B2258197FC91B2C7317444A850237056BF5EE1A5DA6548B2A71039B"
) , (
    "3810682260",
    "18AAB9A72CC63A04C0567AD9A1BCCB36A7E792E0B20C7246D8EE4405918B2B1B"
) , (
    "3810683449",
    "4DC6E7F6432F069CC41D22C10D057C1F991B29C93478506DE34127B72EF5AD9A"
) , (
    "3810684401",
    "D60DE32DCD7825D490B159A4C0B6328EA0EF5A377DDB701D43DABE3EA9B3AA6C"
) , (
    "3810685349",
    "CFBF4BF6BF485DE75393831485A6FC761FB004D573F62A71093159D5AB190605"
) , (
    "3810686522",
    "9A67BC345AA1FEDB824D4759B933CFDA4A76FA57C1847D99EB4877CECF178011"
) , (
    "3874597775",
    "32503F837FBADFF41A6421EC44312A0BEBDAFD365C0B09DDF4D3A50067F99E64"
) , (
    "3874601203",
    "1E5DA627D757855DFE16E0FFE996AD065AF63C104985263C8DB66B68CE744287"
) , (
    "3874603395",
    "8CA34BE0ACEB55042334E7AEF91AE6961E03E4C87B7E68A19210785909EB7091"
) , (
    "3874604816",
    "2DFA97438EB07510C7BEDD8F29AC1A474EBDA106F5343E782CCDB286D17B63C2"
) , (
    "3874606242",
    "7EBE03A901551AD4B83A775EA9940EADEB07A6590F523C28B7BB3AC0ABCA96AE"
) , (
    "3875133952",
    "C6627ACC25DA6E4499838D2B2FB8DE846C8EBBE3D73A057827E8720F8CB67976"
) , (
    "3875135375",
    "D6D80D0028620E5210D5411DCA6A335D6DBC5177757B6D513752DDF3687C3A6E"
) , (
    "3875135872",
    "12E6ED01F1E1E125BF5128382C4E19989734748C5E0D8C8DDB1B75FBE4B584A1"
) , (
    "3875136487",
    "FAE7A27259B5FECB236448DCC501126A28B5325BC662B046FC9D2743729C6C22"
) , (
    "3875136913",
    "794F33DF2AD64CFA618481D30E8C45E3CF54B2D24950F3AD69FAC3DA99EFCA53"
) , (
    "3875137402",
    "193483A87435FA52E868172CB73B44D1B120D570C61826B2AB34098FD6BEB723"
) , (
    "3875138051",
    "C2A0A150D025009D886622CE986265B2CF13DAC0FE70DD7E61D84BA89BAC9F01"
) , (
    "3875138880",
    "D8E4EE73DD9E41A100EC98F6A4201BFB9F24487774F9714A1CC8DC485375DAD3"
) , (
    "3875139623",
    "8E368CEDB9A058A07045E11BC20FAEC9E4470F5677C7ACE14C504004AA156577"
) , (
    "3875140366",
    "018AFA64FA9E8F4AA075905990AD5F539D22386CFAB88FB81EACADE8C7A42F69"
) , (
    "3875142880",
    "8D951E2756C6CE081C9DE26AD1AC9AFA650FC6B5C70EDD391DBA5F0DF4A56263"
) , (
    "3875823815",
    "DBFE9A587948B1450E067F1F74919DAB932F8FC76F4642585202915C96E21421"
) , (
    "3875825268",
    "85489C6A35BCE18760F650D8BC97DA07650C5F037A2D3C9C07435FC6B798FC74"
) , (
    "3875826306",
    "714E48D00CC7DD7DF52402D0A088BFA45480CFD67FA052F44B41A11477C4DFE8"
) , (
    "3875827327",
    "624F8E1B6E79FDC102F1DF9D11063E2A7D993A031D7FF6DF93C22EA6965E04E9"
) , (
    "3875828387",
    "8CB7816C6320AB564064F1596B191FDAB22C41E0A588DBE72423728814B07D74"
) , (
    "3875829393",
    "4D2441F46105F428C69D3FEDD8AB8A0BBE31D9B73C0426B539CAB1C3EADA5816"
) , (
    "3875830479",
    "D548F3E7202F95A3C5D695B677F88E264EC671B13CF2F961C172CCB421F67621"
) , (
    "3875831476",
    "27BD19F350FD9F97C89C4DD663357830FD247B7C03FF03F1B6A415D1BA675112"
) , (
    "3875832499",
    "48BE576DC57B34EE41708DB0A28E0DB80BB5B1232C62F3C02E1B74E6B16A5E53"
) , (
    "3875833673",
    "C379F24213F13732244F803CE8407E265F2528906E564AC06FEF3D9050FA7725"
) , (
    "3875834979",
    "A73F2FECA7661EF8A3D37E1BF435BBBB96348E0DE8B797A6EC1FFDB9D86406D0"
) , (
    "3875836057",
    "CBE39DB908F20E696732CAB5F6F65D5778A0F9FBCC1014E711A5EFE9CD1536E4"
) , (
    "3875836987",
    "D60C2DBACAC31CA37811A2D1EE6987BEF1E43433E7F35ACDD9792308D228F0FB"
) , (
    "3875837982",
    "9354A1AE74B7503BAA88ED5FBFEC3C4FB3D6967AA043AE3075C14E0A1F43F64E"
) , (
    "3875839270",
    "D754BFF203ECE539BDDD4039C18BA93070BC6D78F164DAD300E6E49792B790BE"
) , (
    "3875840214",
    "1D399E59509369037A3DDE1AE800A553AD631FC33FFE8069CDF568CC32276B67"
) , (
    "3875841104",
    "7F9D810368D97A7C94C890229565813BA53814482288D8D807A58B73B7DC2EA0"
) , (
    "3875842351",
    "65211DF792F7DF2F405FD4D24579487B013C0508DF074C935395D896FCA89CE6"
) , (
    "3875843332",
    "4E387AB6D5E1FD32CEA7DFBCE45916ECCE189F32848395C6C714FCC090373AF9"
) , (
    "3875844265",
    "C619698199753E4E4DD521FCB43045CC85D0A1731DA3945CC477F7DDCFDAFEC5"
) , (
    "3875845278",
    "D126CF00B5B6F0EB10A3668CE420AA80C0F6E307C4F3B498C258AD9B2B626945"
) , (
    "3875846250",
    "C7BB93979C165620344FAA4A1923E79649CFF8EF9EF4FAFF555E6994009BCF5E"
) , (
    "3875847160",
    "B0BE8261B2D85522FD6E76A2CAF02C961999F3E43278C18A2F31748F373BB327"
) , (
    "3875848163",
    "025E856E753CD618D3E22663BE9C3C9D42BA1A84540559DEB1C6E3D49CDB5F2F"
) , (
    "3875849143",
    "FFA32EDA1EB710F8C9646AFC55A3E1456860EF34158ED98B57D31BE17E73C964"
) , (
    "3875850209",
    "8A402A6B17027C933C90C52ACB7B10464FEFDB5B04EEF3638B924753906DE724"
) , (
    "3875851073",
    "5FB30B59D2D78A528E70BADCB2C8FF2DC28C6AA5FF5D4C0A677D10E4BEA06304"
) , (
    "3875852129",
    "DE101232051DFF4A6377E9A2349C7359DA0C0ACF615EF913F72794BA7497CAED"
) , (
    "3875853096",
    "2A46EF13F6E7567CBC52B5F18CA925A1C6D1F3AA3D820C457C99E8F80EA50383"
) , (
    "3875941467",
    "012A0502B0C03FCABBF10645774647FE7D5BB03402193081A80BC77B46DCE43A"
) , (
    "3875942475",
    "C2C5DC939633143EBF0B05E1C6D749F9BE53AD75E0B00003CF5FCFC689B68664"
) , (
    "3875943167",
    "6F9BE4ED93D173AFC458ABAFEBE85BD3C47C06EB4D8DC980F69C7AE242737D2F"
) , (
    "3875943932",
    "6FF6CDDEBB70E2DF8E330945BC3925D09C2D77A2BC584405E383F6E0F2B1EEEB"
) , (
    "3875944788",
    "97FBF921031137087A6FAE2F784076772963120F9FFAEFB281D21A3DE6595BE3"
) , (
    "3875945513",
    "F52D50918E49F138059253C8EC5F2EEDED6AF3BD76BDE88124D2D8651B1F60F2"
) , (
    "3875946277",
    "906A7F1EBC883FAC0790676A4BB903DF37A2D7A74977E41C7B16DABAF3A36349"
) , (
    "3875947117",
    "23A3E649088B7AA48BA37B298CE1D88CFB1639AA444399A034940A888BCC5B6B"
) , (
    "3875947923",
    "85B841CC9175034F8D70DFC49FE8857CFB1F672890F9B487120219525C106186"
) , (
    "3875948649",
   "9B6AC6497C4EE635F6A806CD733CB9E0308698A8AA293CDE1839B1DA4F83CF1B"
) ]

def get_token(password, uid):
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    headers = {
        "Host": "ffmconnect.live.gop.garenanow.com",
        "User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "close"
    }
    data = {
        "uid": uid,
        "password": password,
        "response_type": "token",
        "client_type": "2",
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_id": "100067"
    }
    response = requests.post(url, headers=headers, data=data)
    if response.status_code != 200:
        return None
    return response.json()

def parse_response(response_content):
    response_dict = {}
    lines = response_content.split("\n")
    for line in lines:
        if ":" in line:
            key, value = line.split(":", 1)
            response_dict[key.strip()] = value.strip().strip('"')
    return response_dict
    
def process_token_entry(entry):
    uid = entry.get("uid")
    password = entry.get("password")
    if uid and password:
        return process_token(uid, password)
    return None

def process_token(uid, password):
    token_data = get_token(password, uid)
    if not token_data:
        return {"uid": uid, "error": "Failed to retrieve token"}

    game_data = my_pb2.GameData()
    game_data.open_id = token_data['open_id']
    game_data.access_token = token_data['access_token']
    game_data.field_99 = "4"
    serialized_data = game_data.SerializeToString()
    encrypted_data = encrypt_message_direct(AES_KEY, AES_IV, serialized_data)
    hex_encrypted_data = binascii.hexlify(encrypted_data).decode('utf-8')

    url = "https://loginbp.common.ggbluefox.com/MajorLogin"
    headers = {
        'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/octet-stream",
        'Expect': "100-continue",
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': "OB50"
    }

    try:
        response = requests.post(url, data=bytes.fromhex(hex_encrypted_data), headers=headers, verify=False)
        if response.status_code == 200:
            example_msg = output_pb2.Garena_420()
            try:
                example_msg.ParseFromString(response.content)
                return {
                    "uid": uid,
                    "token": parse_response(str(example_msg)).get("token", "N/A")
                }
            except Exception as e:
                return {"uid": uid, "error": f"Parse error: {e}"}
        else:
            return {"uid": uid, "error": f"HTTP {response.status_code}"}
    except Exception as e:
        return {"uid": uid, "error": str(e)}


def encrypt_message(plaintext):
    key = b'Yg&tc%DEuh6%Zc^8'
    iv = b'6oyZDr22E3ychjM%'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(plaintext, AES.block_size)
    encrypted_message = cipher.encrypt(padded_message)
    return binascii.hexlify(encrypted_message).decode('utf-8')

def encrypt_message_direct(key, iv, plaintext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(plaintext, AES.block_size)
    return cipher.encrypt(padded_message)

def create_protobuf_message(user_id, region):
    message = like_pb2.like()
    message.uid = int(user_id)
    message.region = region
    return message.SerializeToString()

async def send_request(encrypted_uid, token, url):
    edata = bytes.fromhex(encrypted_uid)
    headers = {
        'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Authorization': f"Bearer {token}",
        'Content-Type': "application/x-www-form-urlencoded",
        'Expect': "100-continue",
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': "OB50"
    }
    async with aiohttp.ClientSession() as session:
        async with session.post(url, data=edata, headers=headers) as response:
            return response.status

async def send_multiple_requests(uid, server_name, url):
    region = server_name
    protobuf_message = create_protobuf_message(uid, region)
    encrypted_uid = encrypt_message(protobuf_message)
    tasks = []
    tokens = load_tokens(server_name)
    for i in range(100):
        token = tokens[i % len(tokens)]["token"]
        tasks.append(send_request(encrypted_uid, token, url))
    results = await asyncio.gather(*tasks)
    return results

def create_protobuf(uid):
    message = uid_generator_pb2.uid_generator()
    message.krishna_ = int(uid)
    message.teamXdarks = 1
    return message.SerializeToString()

def enc(uid):
    protobuf_data = create_protobuf(uid)
    encrypted_uid = encrypt_message(protobuf_data)
    return encrypted_uid

def make_request(encrypt, server_name, token):
    if server_name == "IND":
        url = "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
    elif server_name in {"BR", "US", "SAC", "NA"}:
        url = "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
    else:
        url = "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"

    edata = bytes.fromhex(encrypt)
    headers = {
        'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Authorization': f"Bearer {token}",
        'Content-Type': "application/x-www-form-urlencoded",
        'Expect': "100-continue",
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': "OB50"
    }

    response = requests.post(url, data=edata, headers=headers, verify=False)
    hex_data = response.content.hex()
    binary = bytes.fromhex(hex_data)
    return decode_protobuf(binary)

def decode_protobuf(binary):
    try:
        items = like_count_pb2.Info()
        items.ParseFromString(binary)
        return items
    except Exception as e:
        print(f"Error decoding Protobuf data: {e}")
        return None

@app.route('/like', methods=['GET'])
def handle_requests():
    uid = request.args.get("uid")
    server_name = request.args.get("server_name", "").upper()
    key = request.args.get("key")

    if key != "TBO":
        return jsonify({"error": "Invalid or missing API key 🔑"}), 403

    if not uid or not server_name:
        return jsonify({"error": "UID and server_name are required"}), 400

    def process_request():
        data = load_tokens(server_name)
        token = data[0]['token']
        encrypt = enc(uid)

        today_midnight = get_today_midnight_timestamp()
        count, last_reset = token_tracker[token]

        if last_reset < today_midnight:
            token_tracker[token] = [0, time.time()]
            count = 0

        if count >= KEY_LIMIT:
            return {
                "error": "Daily request limit reached for this key.",
                "status": 429,
                "remains": f"(0/{KEY_LIMIT})"
            }

        before = make_request(encrypt, server_name, token)
        jsone = MessageToJson(before)
        data = json.loads(jsone)
        before_like = int(data['AccountInfo'].get('Likes', 0))

        # Select URL
        if server_name == "IND":
            url = "https://client.ind.freefiremobile.com/LikeProfile"
        elif server_name in {"BR", "US", "SAC", "NA"}:
            url = "https://client.us.freefiremobile.com/LikeProfile"
        else:
            url = "https://clientbp.ggblueshark.com/LikeProfile"

        asyncio.run(send_multiple_requests(uid, server_name, url))

        after = make_request(encrypt, server_name, token)
        jsone = MessageToJson(after)
        data = json.loads(jsone)

        after_like = int(data['AccountInfo']['Likes'])
        id = int(data['AccountInfo']['UID'])
        name = str(data['AccountInfo']['PlayerNickname'])

        like_given = after_like - before_like
        status = 1 if like_given != 0 else 2

        if like_given > 0:
            token_tracker[token][0] += 1
            count += 1

        remains = KEY_LIMIT - count

        result = {
            "LikesGivenByAPI": like_given,
            "LikesafterCommand": after_like,
            "LikesbeforeCommand": before_like,
            "PlayerNickname": name,
            "UID": id,
            "status": status,
            "remains": f"({remains}/{KEY_LIMIT})"
        }
        return result

    result = process_request()
    return jsonify(result)

@app.route('/jwt', methods=['GET'])
def handle_requests2():
    start_time = time.time()
    token_results = []

    try:
        with open("backup.json", "r") as f:
            user_data = json.load(f)

        max_workers = 20  # Adjust as needed
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(process_token_entry, entry) for entry in user_data]
            for future in as_completed(futures):
                result = future.result()
                if result and "token" in result:
                    token_results.append({
                        "uid": result['uid'],
                        "token": result['token']
                    })

        if token_results:
            with open("token_ind.json", "w") as outfile:
                json.dump(token_results, outfile, indent=2)
        else:
            print("⚠️ No tokens to save.")

    except FileNotFoundError:
        print("⚠️ backup.json file not found.")
    except json.JSONDecodeError:
        print("⚠️ Failed to parse backup.json. Check JSON formatting.")

    end_time = time.time()
    print(f"\n⏳ Completed in {end_time - start_time:.2f} seconds.")
    return jsonify(token_results)

if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)
