from mongoengine import Document, StringField, IntField


class Users(Document):
    username = StringField()
    password = StringField()

