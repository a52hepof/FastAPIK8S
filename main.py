from typing import Optional
from fastapi import FastAPI,Response
import requests
from bs4 import BeautifulSoup
import pandas as pd
from fastapi.responses import FileResponse
import plotly.express as px
import json
from fastapi.testclient import TestClient
import sys
sys.path.append("..")
from fastapi.middleware.cors import CORSMiddleware
import asyncio
from starlette.responses import FileResponse
import time

import jwt

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from fastapi.security import OAuth2PasswordBearer,OAuth2PasswordRequestForm
from passlib.hash import bcrypt

#pip3 install tortoise-orm
# https://coffeebytes.dev/integracion-del-orm-de-python-tortoise-con-fastapi/
from tortoise import Tortoise, fields
from tortoise.models import Model
from tortoise.contrib.fastapi import register_tortoise
from tortoise.contrib.pydantic import pydantic_model_creator




origins = [
    "http://localhost.tiangolo.com",
    "https://localhost.tiangolo.com",
    "http://localhost",
    "http://localhost:8080",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    "http://127.0.0.1:8080",
    "http://127.0.0.1:5000",
    "http://localhost:5000",
]


#uvicorn main:app --host 0.0.0.0 --port 10000


app = FastAPI()
'''
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

'''


JWT_SECRET = 'myjwtsecret'




###############################################
#---------------------------------------------#
## FastAPI modelo de autenticación           ##
#---------------------------------------------#

class User(Model):
    id = fields.IntField(pk=True)
    username = fields.CharField(50, unique=True)
    password_hash = fields.CharField(128)
    companies = fields.CharField(128)

    def verify_password(self, password):
        return bcrypt.verify(password, self.password_hash)


User_Pydantic = pydantic_model_creator(User, name='User')
UserIn_Pydantic = pydantic_model_creator(User, name='UserIn', exclude_readonly=True)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl='token')


async def authenticate_user(username: str, password: str):
    user = await User.get(username=username)
    if not user:
        return False 
    if not user.verify_password(password):
        return False
    return user

@app.post('/token')
async def generate_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await authenticate_user(form_data.username, form_data.password)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail='Invalid username or password'
        )

    user_obj = await User_Pydantic.from_tortoise_orm(user)

    #token = jwt.encode(user_obj.dict(), JWT_SECRET)
    token = jwt.encode(user_obj.dict(), JWT_SECRET)
    ## Esto es un fallo de seguridad se expone el hash de la clave
    #https://jwt.io/
    #companyData.listCompanies=user.companies
    #print(companyData.listCompanies)
    return {'access_token' : token, 'token_type' : 'bearer'}

async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        user = await User.get(id=payload.get('id'))
    except:
        raise HTTPException(
            status_code = status.HTTP_401_UNAUTHORIZED, 
            detail = 'Invalid username or password'
        )

    return await User_Pydantic.from_tortoise_orm(user)

@app.post('/users', response_model=User_Pydantic)
async def create_user(user: UserIn_Pydantic,token: str = Depends(oauth2_scheme)):
#async def create_user(user: UserIn_Pydantic):
    user_obj = User(username=user.username, password_hash=bcrypt.hash(user.password_hash),companies=user.companies)
    #user_obj = User(username=user.username, password_hash=bcrypt.hash(user.password_hash))
    await user_obj.save()
    return await User_Pydantic.from_tortoise_orm(user_obj)


@app.get('/users/me', response_model=User_Pydantic)
async def get_user(user: User_Pydantic = Depends(get_current_user)):
    return user    


'''
userData = get_current_user()
print('Usuario: ', userData.listCompanies)
'''

register_tortoise(
    app, 
    db_url='sqlite://db.sqlite3',
    modules={'modelos': ['main']},
    generate_schemas = True,
    add_exception_handlers=True,
)



def obtenerDatos(fecha=''):

	print((fecha))
	if len(fecha)==0:
		url = "https://tarifaluzhora.es/"
	else:
		dia = fecha.split('-')[0]
		mes = fecha.split('-')[1]
		año = fecha.split('-')[2]
		#https://tarifaluzhora.es/?tarifa=pcb&fecha=14%2F10%2F2022

		url = "https://tarifaluzhora.es/?tarifa=pcb&fecha="+dia+"%2F"+mes+"%2F"+año

	page = requests.get(url)
	soup = BeautifulSoup(page.content, "html.parser")


	return soup


@app.get("/")
async def root():



	soup =obtenerDatos()

	#print(type(df['precio'][0]))

	resultsDia = soup.find(id="price_summary")

	###### Día Consulta

	#print(resultsDia)
	resultsfecha = resultsDia.find("div", class_="gauge_day")

	dia = resultsfecha.find_all("span",class_="sub_text")
	#print("dia fecha",dia)
	for day in dia:
		print(day.text)



	###### Precio hora y día consulta
	resultsPrecioInstantaneo = resultsDia.find("div", class_="gauge_hour")
	horaInstante = resultsPrecioInstantaneo.find_all("h2",class_="title")
	precioInstante = resultsPrecioInstantaneo.find_all("span",class_="sub_text")
	#print(precioInstante)
	#print(horaInstante)

	for precio in precioInstante:
		try:
			print(precio.text.replace('\n',''))
		except:
			pass
	for hora in horaInstante:
		try:
			print(hora.text.split("Precio de la luz a las")[1].replace('\n',''))
		except:
			pass

	###### Precio más alto
	resultsPrecioMasBajo = resultsDia.find("div", class_="gauge_low")

	horaMasBajo = resultsPrecioMasBajo.find_all("span",class_="main_text")
	precioMasBajo = resultsPrecioMasBajo.find_all("span",class_="sub_text")


	#print(horaMasBajo)
	#print(precioMasBajo)
	for precio in precioMasBajo:
		print(precio.text.replace('\n',''))
	for hora in horaMasBajo:
		print(hora.text)

	####### Precio más bajo
	resultsPrecioMasAlto = resultsDia.find("div", class_="gauge_hight")

	horaMasAlto = resultsPrecioMasAlto.find_all("span",class_="main_text")
	precioMasAlto = resultsPrecioMasAlto.find_all("span",class_="sub_text")

	for precio in precioMasAlto:
		print(precio.text.replace('\n',''))
	for hora in horaMasAlto:
		print(hora.text)
	#print(horaMasAlto)
	#print(precioMasAlto)

	obtenerDatos("02-02-2022")



	#return FileResponse("yourfile.png", media_type="image/jpeg", filename="vector_image_for_you.png")
	return {"message": "Candela tráete la bata o si no te la traigo yo, o quizás no o si"}

	#fig = px.scatter(x=[0, 1, 2, 3, 4], y=[0, 1, 4, 9, 1])



@app.get("/precioluz")
def precioluz(user: User_Pydantic = Depends(get_current_user)):
	soup =obtenerDatos()

	results = soup.find(id="hour_prices")
	#print(results.prettify())

	horas = results.find_all("span", itemprop="description")
	precios = results.find_all("span", itemprop="price")
	monedas = results.find_all("meta", itemprop="priceCurrency")
	#monedas = results.find( itemprop="priceCurrency")

	monedasList = []
	preciosList = []
	horasList = []

	#print(precios)

	for moneda in monedas:
		#print(moneda.get('content'))
		monedasList.append(moneda.get('content'))
	for precio in precios:
		#print(precio.text)
		preciosList.append(precio.text.split(' €/kWh')[0])


	for hora in horas:
		print(hora.text.split(':')[0])
		horasList.append(hora.text.split(':')[0])

	df = pd.DataFrame(list(zip(monedasList, preciosList,horasList)), 
	           columns =['Moneda', 'precio','hora'])
	#print(df.sort_values(by=['hora']))
	print(df)

	df['precio']=(df['precio']).astype("float32")
	js = df.to_json(orient = 'records')
	#js = companyDataArval.dataFrameCompany.tail().to_json(orient = 'records')
	jsonObjectData = json.loads(js)
	print(jsonObjectData)



	resultsDia = soup.find(id="price_summary")

	###### Día Consulta

	#print(resultsDia)
	resultsfecha = resultsDia.find("div", class_="gauge_day")

	dia = resultsfecha.find_all("span",class_="sub_text")
	#print("dia fecha",dia)
	for day in dia:
		print(day.text)


	entry = {'dia': day.text}

	jsonObjectData.append(entry)
	return jsonObjectData



	return jsonObjectData




@app.get("/precioluz/{fecha}")
def precioluz(fecha:str):

	soup =obtenerDatos(fecha)

	results = soup.find(id="hour_prices")
	#print(results.prettify())

	horas = results.find_all("span", itemprop="description")
	precios = results.find_all("span", itemprop="price")
	monedas = results.find_all("meta", itemprop="priceCurrency")
	#monedas = results.find( itemprop="priceCurrency")

	monedasList = []
	preciosList = []
	horasList = []

	#print(precios)

	for moneda in monedas:
		#print(moneda.get('content'))
		monedasList.append(moneda.get('content'))
	for precio in precios:
		#print(precio.text)
		preciosList.append(precio.text.split(' €/kWh')[0])


	for hora in horas:
		print(hora.text.split(':')[0])
		horasList.append(hora.text.split(':')[0])

	df = pd.DataFrame(list(zip(monedasList, preciosList,horasList)), 
	           columns =['Moneda', 'precio','hora'])
	#print(df.sort_values(by=['hora']))
	print(df)

	df['precio']=(df['precio']).astype("float32")
	js = df.to_json(orient = 'records')
	#js = companyDataArval.dataFrameCompany.tail().to_json(orient = 'records')
	jsonObjectData = json.loads(js)

	print(jsonObjectData)

	#print(type(df['precio'][0]))

	resultsDia = soup.find(id="price_summary")

	###### Día Consulta

	#print(resultsDia)
	resultsfecha = resultsDia.find("div", class_="gauge_day")

	dia = resultsfecha.find_all("span",class_="sub_text")
	#print("dia fecha",dia)
	for day in dia:
		print(day.text)


	entry = {'dia': day.text}

	jsonObjectData.append(entry)
	return jsonObjectData



@app.get("/grafico/precioluz/")
def precioluzGrafico():
	soup =obtenerDatos()

	results = soup.find(id="hour_prices")
	#print(results.prettify())

	horas = results.find_all("span", itemprop="description")
	precios = results.find_all("span", itemprop="price")
	monedas = results.find_all("meta", itemprop="priceCurrency")
	#monedas = results.find( itemprop="priceCurrency")

	monedasList = []
	preciosList = []
	horasList = []

	#print(precios)

	for moneda in monedas:
		#print(moneda.get('content'))
		monedasList.append(moneda.get('content'))
	for precio in precios:
		#print(precio.text)
		preciosList.append(precio.text.split(' €/kWh')[0])


	for hora in horas:
		print(hora.text.split(':')[0])
		horasList.append(hora.text.split(':')[0])




	df = pd.DataFrame(list(zip(monedasList, preciosList,horasList)), 
	           columns =['Moneda', 'precio','hora'])
	#print(df.sort_values(by=['hora']))
	#print(df)

	df['precio']=(df['precio']).astype("float32")

	resultsDia = soup.find(id="price_summary")

	###### Día Consulta

	#print(resultsDia)
	resultsfecha = resultsDia.find("div", class_="gauge_day")

	dia = resultsfecha.find_all("span",class_="sub_text")
	#print("dia fecha",dia)
	for day in dia:
		print(day.text)

	fig = px.bar(df,x='hora',y='precio', title = day.text)
	img_bytes = fig.to_image(format="png")
	#print(img_bytes)

	#figura= fig.write_image("yourfile.png") 
	#return Response(content=figura, media_type="image/png")
	return Response(content=img_bytes, media_type="image/png")







