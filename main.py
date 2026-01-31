from fastapi import FastAPI, Depends ,HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import List
from fastapi.middleware.cors import CORSMiddleware

from adisyon_veri_tabani import Product,SessionLocal,Order,OrderItem,User,Category

from fastapi.staticfiles import StaticFiles 
from fastapi.responses import FileResponse

import os.path.dirname(os.path.abspath(__file__)
app = FastAPI()
Base_Dır = os.
#dependency_injection
def get_db():

    db = SessionLocal()

    try:
        yield db #bekle
    finally:
        db.close() #kapat

#bu ayar sayesinde html dosyası sunucu ile konuşabilir(CORS AYARI)
app.add_middleware(
    CORSMiddleware,
    allow_origins = ["*"],
    allow_credentials = True,
    allow_methods = ["*"],
    allow_headers = ["*"],
   )

#pydantic_model
#dış dünyaya neyin nasıl gösterileceğini berlirler
class ProductCreate(BaseModel):
    name: str
    price: float
    
class ProductSchema(BaseModel):

    id:int
    name:str
    price:float
    category_id: int

    class Config:
        from_attributes =True #pydantic sadece sözlük veri tipinde çalışır bu satır sayesinde nesne özelliğini de destekler

class SiparişKalemiİsteği(BaseModel):
    product_id: int
    quantity: int
    note: str= ""

class SiparişOluşturmaİsteği(BaseModel):
    table_no: int
    waiter_id: int
    items: List[SiparişKalemiİsteği]

#aşçının göreceği ürün detayı
class MutfakUrunu(BaseModel):
    name: str
    price: float
    class Config:
        from_attributes = True

#aşçının göreceği şipariş kalemi
class MutfakKalemi(BaseModel):
    product : MutfakUrunu
    quantity : int
    note : str | None = None

    class Config:
        from_attributes = True

#aşçının göreceği tam sipariş
class MutfakSiparisi(BaseModel):
    id: int
    table_no: int
    status: str
    items: List[MutfakKalemi]
    
    class Config:
        from_attributes = True

#şipari durumu güncelleme
class DurumGüncelle(BaseModel):
    status: str

#ürün ekleme
class UrunEklemeIsteği(BaseModel):
    name: str
    price: float
    category_id: int

#kategori İçin Modeller
class CategoryCreate(BaseModel):
    name:str

class CategorySchema(BaseModel):
    id: int
    name: str

    class Config:
        from_attributes = True

#kullanıcı için modeller
class UserCreate(BaseModel):
    username: str
    role: str = "garson"

class UserOut(BaseModel):
    username: str
    role: str

    class Config:
        from_attributes = True

#endpoint( tarayıcıda "/products" adresine gidildiğinde çalışacak fonksiyon)
@app.get("/products",response_model = List[ProductSchema])

def urunleri_getir(db: Session = Depends(get_db)):
    tum_urunler = db.query(Product).all()
    return tum_urunler

#endspoint (sipariş oluştur)
@app.post("/orders")
def siparis_olustur(siparis_veri: SiparişOluşturmaİsteği, db: Session = Depends(get_db)):

    yeni_siparis = Order(
        table_no = siparis_veri.table_no,
        waiter_id = siparis_veri.waiter_id,
        status = "Hazirlaniyor"
    )
    db.add(yeni_siparis)
    db.commit()
    db.refresh(yeni_siparis)

    for kalem in siparis_veri.items:
        yeni_kalem = OrderItem(
            order_id = yeni_siparis.id,
            product_id = kalem.product_id,
            quantity = kalem.quantity,
            note = kalem.note
        )
        db.add(yeni_kalem)
    db.commit()

    return {
        "mesaj": "Sipariş başari ile mutfağa iletildi.",
        "fiş_no" : yeni_siparis.id,
        "masa" : yeni_siparis.table_no
    }

#endpoint mutfak şipariş ekranı verisi
@app.get("/kitchen/orders",response_model = List[MutfakSiparisi])
def mutfak_siparişlerini_getir(db:Session = Depends(get_db)):
    aktif_siparisler = db.query(Order).filter(Order.status == "Hazirlaniyor").all()
    return aktif_siparisler

#endpoint sipariş durum güncelleme
@app.put("/orders/{order_id}/status")
def durum_degistir(order_id: int, durum_verisi: DurumGüncelle, db: Session = Depends(get_db)):
    siparis = db.query(Order).filter(Order.id == order_id).first()

    if not siparis:
        raise HTTPException(status_code=404, detail = "Sipariş Bulunamadi")
    
    eski_durum = siparis.status
    siparis.status = durum_verisi.status
    db.commit()

    return{ "mesaj":f"Sipariş {eski_durum} surumundan {siparis.status} durumuna geçti."}

#ürünleri listeleme
@app.get("/products", response_model = List[ProductSchema])
def urunleri_getir(db: Session = Depends(get_db)):
    tum_urunler = db.query(Product).all()
    return tum_urunler

#ürün ekleme
@app.post("/products")
def urun_ekle(urun: UrunEklemeIsteği, db: Session = Depends(get_db)):
    yeni_urun = Product(
        name = urun.name,
        price = urun.price,
        category_id = urun.category_id,
    )
    db.add(yeni_urun)
    db.commit()
    db.refresh(yeni_urun)

    return {"mesaj":"Ürün eklendi", "urun":yeni_urun}

@app.get("/cashier/orders", response_model = List[MutfakSiparisi])
def kasa_siparisleri_getir(db: Session = Depends(get_db)):
    aktif_siparisler = db.query(Order).filter(Order.status != "Ödendi").all()
    return aktif_siparisler

@app.post("/categories", response_model = CategorySchema)
def kategory_oluştur(kategori: CategoryCreate, db: Session = Depends(get_db)):
    yeni_kategori = Category(name = kategori.name)
    db.add(yeni_kategori)
    db.commit()
    db.refresh(yeni_kategori)
    return yeni_kategori

@app.get("/categories", response_model = List[CategorySchema])
def kategorileri_getir(db:Session = Depends(get_db)):
    return db.query(Category).all()

@app.get("/")
async def ana_sayfa():
    return FileResponse(os.path.join(Base_Dır,'garson.html'))

app.get("/garson")
async def get_garson():
    return FileResponse(os.path.join(Base_Dır,'garson.html'))

@app("/kasa")
async def get_kasa():
    return FileResponse(os.path.join(Base_Dır,'kasa.html'))

@app("/mutfak")
async def get_mutfak():
    return FileResponse(os.path.join(Base_Dır,'mutfak.html'))

@app("/admin")
async def get_admin():
    return FileResponse(os.path.join(Base_Dır,'admin.html'))
































# # Statik dosyaları (HTML, CSS) sunmak için mount işlemi
# app.mount("/static", StaticFiles(directory="static"), name="static")

# # Arayüzlere kolay erişim için endpointler
# @app.get("/garson")
# async def get_garson():
#     return FileResponse('static/garson.html')

# @app.get("/mutfak")
# async def get_mutfak():
#     return FileResponse('static/mutfak.html')

# @app.get("/kasa")
# async def get_kasa():
#     return FileResponse('static/kasa.html')

# @app.get("/admin")
# async def get_admin():

#     return FileResponse('static/admin.html')

