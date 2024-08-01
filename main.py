import os
from dotenv import load_dotenv
from pymongo import MongoClient

from tokenization import tokenize, detokenize, remove_non_alphanumeric_values


def main():
    # Load the database URL from .env file
    load_dotenv()
    db_url = os.getenv("DATABASE_URL")

    # Connect to MongoDB
    client = MongoClient(db_url)
    db = client.get_database()
    print(db)
    # Insert user document into userData collection
    client_data = {
        "name": "John Doe",
        "pesel": "12345678901",
        "idNumber": "ABC-123456",
        "email": "johndoe@example.com",
        "phone": "123456789",
        "agreements": "[]", # dlp API accepts strings only
        "userId": "adyuhfkb",
        "companies": "[]", # dlp API accepts strings only
    }
    # if you deidentify/identify with deterministic encryption, you don't need to remove non-alphanumeric characters
    remove_non_alphanumeric_values(client_data["idNumber"])

    # tokenize data
    # there is possibility to put only fields required to deidentify into function
    tokenized_data = dict(tokenize([client_data])[0]) # you can also tokenize multiple records at once
    print("Tokenized Data",tokenized_data)

    # insert data
    client_collection = db.get_collection("Client")
    client_collection.insert_one(tokenized_data)
    # client_collection.insert_many(tokenized_data)

    # retrieve data
    result = client_collection.find_one(tokenized_data)
    print("Tokenized data retrieved from database", result)

    # remove id key from result as you have to put the same document into detokenize function
    result.pop('_id')

    # identify data
    detokenized_data = detokenize([result])
    print("Detokenized Results\n", detokenized_data)

    # Close the MongoDB connection
    client.close()


if __name__ == "__main__":
    main()
