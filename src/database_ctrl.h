/*!
 * \file DatabaseCtrl.h
 * \brief Database controller class and function definitions
 */

#ifndef ZTP_DATABASE_CTRL_H
#define ZTP_DATABASE_CTRL_H

#include <bsoncxx/builder/stream/document.hpp>
#include <bsoncxx/json.hpp>

#include <mongocxx/client.hpp>
#include <mongocxx/stdx.hpp>

class DatabaseCtrl
{
private:
    mongocxx::database m_db;
    mongocxx::client m_client;

public:
    explicit DatabaseCtrl(const char *db_name);

    /// FindOne - Find an entry from the database. Throw an exception if entry is not found.
    /// @param coll_name Collection name
    /// @param bson_val Query as BSON object
    /// @return Optional BSON document
    bsoncxx::stdx::optional<bsoncxx::document::value>
    find_one(const char *coll_name, const bsoncxx::document::view_or_value& bson_val) const;

    /// DeleteOne - Delete an entry from the database.
    /// @param coll_name Collection name
    /// @param bson_val Query as BSON object
    /// @return Optional BSON document
    bsoncxx::stdx::optional<mongocxx::result::delete_result>
    delete_one(const char *coll_name, const bsoncxx::document::view_or_value& bson_val) const;

    /// InsertOne - Insert an entry to the database.
    /// @param coll_name Collection name
    /// @param bson_val Query as BSON object
    /// @return Optional
    bsoncxx::stdx::optional<mongocxx::result::insert_one>
    insert_one(const char *coll_name, const bsoncxx::document::view_or_value& bson_val) const;

    bsoncxx::stdx::optional<mongocxx::result::update>
    update_one(const char *coll_name, const bsoncxx::document::view_or_value &bson_val,
               const bsoncxx::document::view_or_value &updated_val) const;

    mongocxx::cursor
    find_many(const char *coll_name, const bsoncxx::document::view_or_value& bson_val) const;
};


#endif //ZTP_DATABASE_CTRL_H