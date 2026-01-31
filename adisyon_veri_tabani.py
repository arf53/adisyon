from sqlalchemy import create_engine,Column,Integer,String,Boolean,ForeignKey,Float
from sqlalchemy.orm import declarative_base,sessionmaker, relationship
import os

#veritabanı_motoru
DataBase_url = os.environ.get("DataBase_url")
if DataBase_url and DataBase_url .startswith("postgres://"):
    DataBase_url = DataBase_url.replaca("postgres://", "postgresgl://",1)

if not DataBase_url:
    DataBase_url = "sqlite:///adisyon_sistemi.db"
    connect_args = {"check_same_thread" : False}
else:
    connect_args ={}

engine = create_engine(DataBase_url, connect_args = connect_args)

# DataBase_url = 'postgresql://neondb_owner:npg_IQxY2dJNn3Lr@ep-shy-frog-ahdb686n-pooler.c-3.us-east-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require'
# engine = create_engine(DataBase_url)

#oturum_yöneticisi
#veritabanı ile konuşacak olan temsilci
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

#python sınıflarının veritabanı tablosu olduğunu belirten temel sınıf(base_class)
Base = declarative_base()

class User(Base):
    __tablename__="users"

    id = Column(Integer, primary_key= True, index=True)
    username = Column(String, unique=True, index=True)
    password = Column(String)
    role = Column(String)
    
    orders =relationship("Order", back_populates="waiter")


class Category(Base):
    __tablename__="categories"

    id = Column(Integer, primary_key= True, index=True)
    name = Column(String,unique=True)

    products = relationship("Product",back_populates="category")


class Product(Base):
    __tablename__="products"

    id = Column(Integer,primary_key=True, index= True)
    name = Column(String)
    price = Column(Float)
    is_active = Column(Boolean, default=True)

    category_id = Column(Integer, ForeignKey("categories.id"))

    category = relationship("Category", back_populates="products")


class Order (Base):
    __tablename__="orders"

    id = Column(Integer,primary_key=True, index=True)
    table_no = Column(Integer)
    status = Column(String, default="Hazirlaniyor")
    
    waiter_id = Column(Integer, ForeignKey("users.id"))

    waiter = relationship("User", back_populates="orders")
    items = relationship("OrderItem",back_populates="order")


class OrderItem(Base):

    __tablename__="order_items"
    id = Column(Integer,primary_key=True,index=True)


    order_id = Column(Integer,ForeignKey("orders.id"))
    product_id = Column(Integer,ForeignKey("products.id"))
    quantity = Column(Integer)
    note =  Column(String)
 
    order = relationship("Order",back_populates="items")
    product =relationship("Product")

if __name__ == "__main__":
    print("veritabani oluşturuluyor...")
    Base.metadata.create_all(bind=engine)
    print("Başarili!'adisyon_sistemi.db' oluşturuldu." )




