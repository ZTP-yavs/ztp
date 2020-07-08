#pragma once

#include <sw/redis++/redis++.h>


namespace RedisLayer{
    using namespace sw::redis;
    static Redis redis = Redis("tcp://auth:1234@127.0.0.1:6379"); // namespace haline getircez

}