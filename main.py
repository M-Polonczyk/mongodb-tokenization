import os
from dotenv import load_dotenv
from pymongo import MongoClient

from tokenization import Tokenization


def main():
    """This is the sample use case for mongodb"""
    # Load the database URL from .env file
    load_dotenv()
    db_url = os.getenv("DATABASE_URL")

    identyfication_methods = ["deterministic", "fpe"]
    identyfication_method = identyfication_methods[1]
    template_name = None
    surrogate_type = None

    # Connect to MongoDB
    client = MongoClient(db_url)
    db = client.get_database()

    # Insert sample document into collection
    data = {
        "name": "John Doe",
        "email": "johndoe@example.com",
        "idNumber": "ABC-123456",
        "phone": "123456789",
        "companies": "[]",  # dlp API accepts strings only
    }
    
    tokenization = Tokenization(
        [data], identyfication_method, template_name, surrogate_type
    )

    # tokenize data
    # there is possibility to put only fields required to deidentify into function
    tokenized_data = dict(
        tokenization.tokenize([data])[0]
    )  # you can also tokenize multiple records at once
    print("Tokenized Data", tokenized_data)

    # insert data
    client_collection = db.get_collection("Client")
    client_collection.insert_one(tokenized_data)
    # client_collection.insert_many(tokenized_data)

    # retrieve data
    result = client_collection.find_one(tokenized_data)
    print("Tokenized data retrieved from database", result)
    if result is None:
        exit()
    # remove id key from result as you have to put the same document into detokenize function
    result.pop("_id")

    # identify data
    detokenized_data = tokenization.detokenize([result])
    print("Detokenized Results\n", detokenized_data)

    # Close the MongoDB connection
    client.close()


if __name__ == "__main__":
    main()
