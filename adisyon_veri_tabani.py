from sqlalchemy import create_engine, Column, Integer, String, Boolean, ForeignKey, Float
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
import os

# 1. VERİTABANI MOTORU VE URL DÜZELTME
DataBase_url = os.environ.get("DataBase_url")

if DataBase_url and DataBase_url.startswith("postgres://"):
    # Yazım hataları düzeltildi: replace ve postgresql
    DataBase_url = DataBase_url.replace("postgres://", "postgresql://", 1)

if not DataBase_url:
    DataBase_url = "sqlite:///adisyon_sistemi.db"
    connect_args = {"check_same_thread": False}
else:
    connect_args = {}

engine = create_engine(DataBase_url, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# 2. MODELLER (Multi-Restaurant Desteği Geri Eklendi)

class Restaurant(Base):
    __tablename__ = "restaurants"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True)
    address = Column(String, nullable=True)

    users = relationship("User", back_populates="restaurant")
    categories = relationship("Category", back_populates="restaurant")
    products = relationship("Product", back_populates="restaurant")
    orders = relationship("Order", back_populates="restaurant")

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    restaurant_id = Column(Integer, ForeignKey("restaurants.id"))
    username = Column(String, index=True)
    password = Column(String)
    role = Column(String)
    
    restaurant = relationship("Restaurant", back_populates="users")
    orders = relationship("Order", back_populates="waiter")

class Category(Base):
    __tablename__ = "categories"
    id = Column(Integer, primary_key=True, index=True)
    restaurant_id = Column(Integer, ForeignKey("restaurants.id"))
    name = Column(String)

    restaurant = relationship("Restaurant", back_populates="categories")
    products = relationship("Product", back_populates="category")

class Product(Base):
    __tablename__ = "products"
    id = Column(Integer, primary_key=True, index=True)
    restaurant_id = Column(Integer, ForeignKey("restaurants.id"))
    name = Column(String)
    price = Column(Float)
    is_active = Column(Boolean, default=True)
    category_id = Column(Integer, ForeignKey("categories.id"))

    restaurant = relationship("Restaurant", back_populates="products")
    category = relationship("Category", back_populates="products")
    order_items = relationship("OrderItem", back_populates="product")

class Order(Base):
    __tablename__ = "orders"
    id = Column(Integer, primary_key=True, index=True)
    restaurant_id = Column(Integer, ForeignKey("restaurants.id"))
    table_no = Column(Integer)
    status = Column(String, default="Hazirlaniyor")
    waiter_id = Column(Integer, ForeignKey("users.id"))

    restaurant = relationship("Restaurant", back_populates="orders")
    waiter = relationship("User", back_populates="orders")
    items = relationship("OrderItem", back_populates="order")

class OrderItem(Base):
    __tablename__ = "order_items"
    id = Column(Integer, primary_key=True, index=True)
    order_id = Column(Integer, ForeignKey("orders.id"))
    product_id = Column(Integer, ForeignKey("products.id"))
    quantity = Column(Integer)
    note = Column(String)
 
    order = relationship("Order", back_populates="items")
    product = relationship("Product", back_populates="order_items")

# 3. TABLOLARI OLUŞTUR (Vercel için blok dışına alındı)
Base.metadata.create_all(bind=engine)

if __name__ == "__main__":
    print("Veritabanı tabloları kontrol edildi ve oluşturuldu.")





