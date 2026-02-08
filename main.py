from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import List
from fastapi.middleware.cors import CORSMiddleware
import os
from datetime import datetime, timedelta

from adisyon_veri_tabani import Product, SessionLocal, Order, OrderItem, User, Category, Restaurant
from fastapi.responses import FileResponse
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt

from contextlib import asynccontextmanager
from adisyon_veri_tabani import Base, engine

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Uygulama başlarken tabloları oluştur
    Base.metadata.create_all(bind=engine)
    yield

# FastAPI tanımınızı şu şekilde güncelleyin:
app = FastAPI(lifespan=lifespan)

# --- GÜVENLİK AYARLARI ---
SECRET_KEY = "safdafdsgfdhggJHIK(UYJHMJOKYR5rythytehghkjg/*-ghjd*/)"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 600

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Giriş Yapılamadı",
        headers={"WWW-Authenticate": "Bearer"}
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        restaurant_id: int = payload.get("restaurant_id")
        if username is None or restaurant_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    user = db.query(User).filter(User.username == username, User.restaurant_id == restaurant_id).first()
    if user is None:
        raise credentials_exception
    return user

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- MODELLER ---
class ProductCreate(BaseModel):
    name: str
    price: float
    category_id: int

class SiparisKalemi(BaseModel):
    product_id: int
    quantity: int
    note: str = ""

class SiparisCreate(BaseModel):
    table_no: int
    items: List[SiparisKalemi]

class MutfakUrunu(BaseModel):
    name: str
    price: float
    class Config:
        from_attributes = True

class MutfakKalemi(BaseModel):
    product: MutfakUrunu
    quantity: int
    note: str | None = None
    class Config:
        from_attributes = True

class MutfakSiparisi(BaseModel):
    id: int
    table_no: int
    status: str
    items: List[MutfakKalemi]
    class Config:
        from_attributes = True

class DurumGüncelle(BaseModel):
    status: str

class CategoryCreate(BaseModel):
    name: str

class UserCreate(BaseModel):
    username: str
    password: str
    role: str = "garson"

class RestaurantCreate(BaseModel):
    restaurant_name: str
    admin_username: str
    admin_password: str

# --- ENDPOINTLER ---

@app.post("/orders")
def siparis_ver(siparis: SiparisCreate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    new_order = Order(
        table_no=siparis.table_no,
        waiter_id=current_user.id,
        restaurant_id=current_user.restaurant_id,
        status="Hazirlaniyor"
    )
    db.add(new_order)
    db.commit()
    db.refresh(new_order)
    
    for item in siparis.items:
        order_item = OrderItem(
            order_id=new_order.id,
            product_id=item.product_id,
            quantity=item.quantity,
            note=item.note
        )
        db.add(order_item)
    db.commit()
    return {"mesaj": "Sipariş alındı", "id": new_order.id}

@app.get("/kitchen/orders", response_model=List[MutfakSiparisi])
def mutfak_siparisleri(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(Order).filter(
        Order.restaurant_id == current_user.restaurant_id,
        Order.status == "Hazirlaniyor"
    ).all()

@app.put("/orders/{order_id}/status")
def durum_degistir(order_id: int, durum_verisi: DurumGüncelle, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    siparis = db.query(Order).filter(Order.id == order_id, Order.restaurant_id == current_user.restaurant_id).first()
    if not siparis:
        raise HTTPException(status_code=404, detail="Sipariş bulunamadı")
    siparis.status = durum_verisi.status
    db.commit()
    return {"mesaj": "Durum güncellendi"}

@app.get("/products")
def urunleri_getir(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(Product).filter(Product.restaurant_id == current_user.restaurant_id).all()

@app.post("/products")
def urun_ekle(prod: ProductCreate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    new_prod = Product(name=prod.name, price=prod.price, category_id=prod.category_id, restaurant_id=current_user.restaurant_id)
    db.add(new_prod)
    db.commit()
    return {"mesaj": "Ürün eklendi"}

@app.get("/cashier/orders", response_model=List[MutfakSiparisi])
def kasa_siparisleri_getir(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(Order).filter(Order.restaurant_id == current_user.restaurant_id, Order.status != "Ödendi").all()

@app.post("/categories")
def kategori_ekle(cat: CategoryCreate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    new_cat = Category(name=cat.name, restaurant_id=current_user.restaurant_id)
    db.add(new_cat)
    db.commit()
    return {"mesaj": "Kategori eklendi"}

@app.get("/categories")
def kategorileri_getir(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(Category).filter(Category.restaurant_id == current_user.restaurant_id).all()

@app.post("/register_restaurant")
def isletme_kayit(data: RestaurantCreate, db: Session = Depends(get_db)):
    if db.query(Restaurant).filter(Restaurant.name == data.restaurant_name).first():
        raise HTTPException(status_code=400, detail="Bu işletme adı zaten kullanılıyor")
    new_restaurant = Restaurant(name=data.restaurant_name)
    db.add(new_restaurant)
    db.commit()
    db.refresh(new_restaurant)
    new_admin = User(username=data.admin_username, password=get_password_hash(data.admin_password), role="admin", restaurant_id=new_restaurant.id)
    db.add(new_admin)
    db.commit()
    return {"mesaj": "İşletme oluşturuldu"}

@app.post("/token")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.password):
        raise HTTPException(status_code=400, detail="Hatalı kullanıcı adı veya şifre")
    access_token = create_access_token(data={"sub": user.username, "restaurant_id": user.restaurant_id, "role": user.role})
    return {"access_token": access_token, "token_type": "bearer", "role": user.role}

@app.post("/users")
def personel_ekle(user: UserCreate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Yetkisiz işlem")
    new_user = User(username=user.username, password=get_password_hash(user.password), role=user.role, restaurant_id=current_user.restaurant_id)
    db.add(new_user)
    db.commit()
    return {"mesaj": "Personel eklendi"}

# --- SAYFA YÖNLENDİRMELERİ ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

@app.get("/")
async def ana_sayfa():
    return FileResponse(os.path.join(BASE_DIR, 'login.html'))

@app.get("/login.html")
async def get_login():
    return FileResponse(os.path.join(BASE_DIR, 'login.html'))

@app.get("/register.html")
async def get_register():
    return FileResponse(os.path.join(BASE_DIR, 'register.html'))

@app.get("/garson.html")
async def get_garson():
    return FileResponse(os.path.join(BASE_DIR, 'garson.html'))

@app.get("/mutfak.html")
async def get_mutfak():
    return FileResponse(os.path.join(BASE_DIR, 'mutfak.html'))

@app.get("/kasa.html")
async def get_kasa():
    return FileResponse(os.path.join(BASE_DIR, 'kasa.html'))

@app.get("/admin.html")
async def get_admin():
    return FileResponse(os.path.join(BASE_DIR, 'admin.html'))








