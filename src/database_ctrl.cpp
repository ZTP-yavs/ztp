//
// Created by aeryz on 11/20/19.
//
#include <iostream>
#include "database_ctrl.h"

using bsoncxx::builder::stream::document;
using bsoncxx::builder::stream::finalize;

#define DB_URI "mongodb://localhost:27017"

DatabaseCtrl::DatabaseCtrl(const char *db_name) {
    m_client = mongocxx::client{mongocxx::uri{DB_URI}};
    if (!m_client)
        throw std::runtime_error("Couldn't connect to DB");

    m_db = m_client[db_name];
    if (!m_db)
        throw std::runtime_error("Couldn't connect to the database");
}

bsoncxx::stdx::optional<bsoncxx::document::value>
DatabaseCtrl::find_one(const char *coll_name, const bsoncxx::document::view_or_value &bson_val) const {
    auto collection = m_db[coll_name];

    if (!collection)
        throw std::runtime_error("Couldn't get the collection");

    return collection.find_one(bson_val);
}

bsoncxx::stdx::optional<mongocxx::result::delete_result>
DatabaseCtrl::delete_one(const char *coll_name, const bsoncxx::document::view_or_value &bson_val) const {
    mongocxx::collection collection = m_db[coll_name];
    if (!collection)
        throw std::runtime_error("Couldn't get the collection");

    return collection.delete_one(bson_val);

}

bsoncxx::stdx::optional<mongocxx::result::insert_one>
DatabaseCtrl::insert_one(const char *coll_name, const bsoncxx::document::view_or_value &bson_val) const {
    mongocxx::collection collection = m_db[coll_name];
    if (!collection)
        throw std::runtime_error("Couldn't get the collection");
    return collection.insert_one(bson_val);
}

bsoncxx::stdx::optional<mongocxx::result::update>
DatabaseCtrl::update_one(const char *coll_name, const bsoncxx::document::view_or_value &bson_val,
                         const bsoncxx::document::view_or_value &updated_val) const {
    mongocxx::collection collection = m_db[coll_name];
    if (!collection)
        throw std::runtime_error("Couldn't get the collection");

    return collection.update_one(bson_val, updated_val);
}

mongocxx::cursor
DatabaseCtrl::find_many(const char *coll_name, const bsoncxx::document::view_or_value& bson_val) const
{
    mongocxx::collection collection = m_db[coll_name];
    if (!collection)
        throw std::runtime_error("Couldn't get the collection");
    return collection.find(bson_val);
}