from django.shortcuts import render, redirect
from index import models
from django.http import FileResponse, JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
import os
from index.untils import judge_filepath, format_size
from django.utils import timezone
from django.utils.http import urlquote
from django.contrib import auth
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from index.models import Keys
import shutil
import random
import string
import base64
import hashlib
import json
from Crypto import Random
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5
from Crypto.PublicKey import RSA
from django.http import HttpResponseRedirect


# Create your views here.
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@login_required
def index(request):
    user = request.user
    user_id = User.objects.get(username=user).id
    file_obj = models.FileInfo.objects.filter(user_id=user_id, belong_folder='')
    folder_obj = models.FolderInfo.objects.filter(user_id=user_id, belong_folder='')
    index_list = []
    for file in file_obj:
        file.is_file = True
        index_list.append(file)
    for folder in folder_obj:
        folder.is_file = False
        index_list.append(folder)
    breadcrumb_list = [{'tag': '全部文件', 'uri': ''}]
    return render(request, 'index.html',
                  {'index_list': index_list, 'username': str(user), 'breadcrumb_list': breadcrumb_list})


@login_required
def folder(request):
    user = request.user
    user_id = User.objects.get(username=user).id
    pdir = request.GET.get('pdir')
    if pdir:
        if pdir[-1:] == '/':
            belong_folder = pdir
        else:
            belong_folder = pdir + '/'
    else:
        belong_folder = ''
    file_obj = models.FileInfo.objects.filter(user_id=user_id, belong_folder=belong_folder)
    folder_obj = models.FolderInfo.objects.filter(user_id=user_id, belong_folder=belong_folder)
    index_list = []
    for file in file_obj:
        file.is_file = True
        index_list.append(file)
    for folder in folder_obj:
        folder.is_file = False
        index_list.append(folder)
    breadcrumb_list = [{'tag': '全部文件', 'uri': ''}]
    uri = ''
    for value in pdir.split('/'):
        if value:
            uri = uri + value + '/'
            breadcrumb_list.append({'tag': value, 'uri': uri})
    return render(request, 'index.html',
                  {'index_list': index_list, 'username': str(user), 'breadcrumb_list': breadcrumb_list})


@login_required
def delete_file(request):
    user = str(request.user)
    user_id = User.objects.get(username=user).id
    file_path = request.GET.get('file_path')
    pwd = request.GET.get('pwd')
    models.FileInfo.objects.get(file_path=file_path, user_id=user_id).delete()
    try:
        os.remove(BASE_DIR + '/User/' + file_path)
    except Exception as e:
        print(e)
    return redirect('/folder/?pdir=' + pwd)



@login_required
def delete_folder(request):
    user = request.user
    pwd = request.GET.get('pwd')
    folder_name = request.GET.get('folder_name')
    try:
        models.FolderInfo.objects.filter(belong_folder__contains=folder_name).delete()
        models.FolderInfo.objects.filter(folder_name=folder_name).delete()
        models.FileInfo.objects.filter(belong_folder__contains=folder_name).delete()
        rm_dir = BASE_DIR + '/User/' + str(user) + '/' + pwd + folder_name
        shutil.rmtree(rm_dir)
    except Exception as e:
        print(e)
    return redirect('/folder/?pdir=' + pwd)


@login_required
def mkdir(request):
    user = request.user
    user_id = User.objects.get(username=user).id
    pwd = request.GET.get('pwd')
    folder_name = request.GET.get('folder_name')
    update_time = timezone.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        models.FolderInfo.objects.create(user_id=user_id, folder_name=folder_name, belong_folder=pwd,
                                         update_time=update_time)
        user_path = os.path.join(BASE_DIR, 'User', str(user))
        os.mkdir(user_path + '/' + pwd + folder_name)
    except Exception as e:
        print(e)
    return redirect('/folder/?pdir=' + pwd)


@login_required
def download_file(request):
    file_path = request.POST.get('file_path')
    file_name = file_path.split('/')[-1]
    file_dir = BASE_DIR + '/User/' + file_path
    enfile = open(file_dir, 'rb').read()   
    fileinfo = models.FileInfo.objects.get(file_path=file_path)
    enfileKey = fileinfo.enfilekey
    #response = FileResponse(file)
    #response['Content-Type'] = 'application/octet-stream'
    #response['Content-Disposition'] = 'attachment;filename={}'.format(urlquote(file_name))
    #return response
    content={'fileName': file_name, 'enfile':str(enfile.decode()),'enfileKey':enfileKey}
    return JsonResponse(content, safe=False)

@login_required
def upload_file(request):
    if request.method == "POST":
        user_name = str(request.user)
        user_obj = User.objects.get(username=user_name)
        file_obj = request.FILES.get('file')
        file_type = judge_filepath(file_obj.name.split('.')[-1].lower())
        pwd = request.POST.get('file_path')
        print(pwd)
        enfile = request.POST.get('enfile')
        enfileKey = request.POST.get('enfileKey')
        print(enfile)
        update_time = timezone.now().strftime("%Y-%m-%d %H:%M:%S")
        file_size = format_size(file_obj.size)
        print("+-"*40)
        print(file_size)
        if(file_size == None):
            file_size = " "
        file_name = file_obj.name
        save_path = BASE_DIR + '/User/' + user_name + '/' + pwd
        file_path = user_name + '/' + pwd + file_name
        # print(belong_folder, folder_name, save_path)
        models.FileInfo.objects.create(user_id=user_obj.id, file_path=file_path,
                                       file_name=file_name, update_time=update_time, belong_folder=pwd, enfilekey=enfileKey,file_type=file_type,file_size=file_size)
        enfi = bytes(enfile,encoding="utf-8")
        with open(save_path + file_name, 'wb+') as f:
            f.write(enfi)
            f.close()
            #for chunk in file_obj.chunks():
                #f.write(chunk)
        return redirect('/')

@login_required
def file_type(request):
    user = request.user
    file_type = request.GET.get('file_type')
    user_id = User.objects.get(username=user).id
    file_list = []
    if file_type == 'all':
        file_obj = models.FileInfo.objects.filter(user_id=user_id)
    else:
        file_obj = models.FileInfo.objects.filter(file_type=file_type, user_id=user_id)
    for file in file_obj:
        file_list.append({'file_path': file.file_path, 'file_name': file.file_name,
                          'update_time': str(file.update_time), 
                          'file_type': file.file_type,
                           'file_size':file.file_size})
    return JsonResponse(file_list, safe=False)



def login(request):
    if request.method == 'GET':
        return render(request, 'login.html')
    elif request.method == "POST":
        username = request.POST.get('username')
        print("username = ",username)
        user = request.user
        #print(user)
#        user_id = User.objects.get(username=user).id
        USER = models.Keys.objects.get(user=username)
        
        print(USER.enprivateKey)
        enmasterKey = USER.enmasterKey
        print("enmasterKey=",enmasterKey)
        

        enprivateKey = USER.enprivateKey
        publicKey = USER.publicKey
        token = USER.token[0:30]

        content = token.encode('utf-8')
        print(content)
        print(publicKey)
        print("sss",len(token))
        print(type(publicKey))
        #rsa_public_key = '-----BEGIN PUBLIC KEY-----\n' + str(publicKey) + '\n-----END PUBLIC KEY-----\n';
        
        #rsa_public_key = '-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC9V3P/Ci5+MY2dqxkiABWG2VcR6eJYhXmNy6SDkHxCf3b9Hdey3Djy1ToTouGggE6aP+9yhZ/sb9daeKW5kc3p2JhJvyjuewOqwkA7rysuUxoYIqg4royaS497n3c3igDS0RACk23cGb3FIi+QQ05mjucYcvDx0N7QSohQrSpMwQIDAQAB\n-----END PUBLIC KEY-----\n'
       # newkey = bytes(rsa_public_key,encoding="utf-8")
        newkey = bytes(publicKey,encoding="utf-8")
        rsakey = RSA.importKey(newkey)
        cipher = Cipher_pkcs1_v1_5.new(rsakey)
        cipher_text = base64.b64encode(cipher.encrypt(bytes(token,encoding="utf-8")))
        print(cipher_text)
        enToken = str(cipher_text, encoding = "utf-8")

        #enToken = rsa.encrypt(content, publicKey)    

        content = {
            'enmasterKey': enmasterKey,
            'enprivateKey': enprivateKey,
            'publicKey': publicKey,
            'enToken': enToken
        }
#        print(response)
        return JsonResponse(content)
        #return redirect('/register')
#        return HttpResponse(json.dumps(response))

def checkToken(request):
    if request.method == "POST":
        #print("request = ",request)
        username = request.POST.get('username')
        print("IN_views.checkToken()")
        print("username_in_check_Token:",username)
        inputToken = request.POST.get('token')
        #user = models.Keys.objects.get(token=inputToken)
        print("inputToken_from_client = ",inputToken)
        #print("user = ",user)
        user = auth.authenticate(username=username, password='123')
        if user:
            auth.login(request, user)
            print("LOGIN_SUCCEED")
#            return redirect('/')            
            return HttpResponseRedirect('/')
        else:
            print("!"*40)
            return redirect('register')


@csrf_exempt
def register(request):
    print("request:",request)
    print("request.POST",request.POST)
    if request.method == 'GET':
        return render(request, 'register.html')


    elif request.method == "POST":
        print("IN_views.register()\n\n")
        username = request.POST.get('username')
        print("username = ",username,"\n\n")
        user_path = os.path.join(BASE_DIR, 'User', username)
        enmasterKey = request.POST.get('enmasterKey')
        print("enmasterKey = ",enmasterKey,"\n\n")
        #enmasterKey = "111"
        enprivateKey = request.POST.get('enprivateKey')
        print("enprivateKey = ",enprivateKey,"\n\n")
        #enprivateKey = "222"
        publicKey = request.POST.get('publicKey')
        print("publicKey = ",publicKey,"\n\n")
        #publicKey = "333"


        token = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(128))[0:30]
        print("Access_Token = ",token,"\n\n")
       # string = (''.join(random.sample(['z','y','x','w','v','u','t','s','r','q','p','o','n','m','l','k','j','i','h','g','f','e','d','c','b','a'], 20)).encode(encoding='utf-8')
       # token = (hashlib.md5(base64.b64encode(string))).hexdigest()
        try:
            User.objects.create_user(username=username, password='123')
            
            #print("1111111")
            Keys.objects.create(user=username, enmasterKey=enmasterKey, enprivateKey=enprivateKey, publicKey=publicKey, token=token)
            print("Object_Created!!!\n\n")
            #print("2222222")
        except Exception as e:
            print("your fault is :",str(e))
            return render(request, 'register.html', {'info': '用户已存在'})
        os.mkdir(user_path)
    else:
        return render(request, 'register.html', {'info': '两次密码不一致'})
    return redirect('login')




def logout(request):
    auth.logout(request)
    return redirect('/')


def page_not_found(request):
    return render(request, '404.html')


def page_error(request):
    return render(request, '500.html')

