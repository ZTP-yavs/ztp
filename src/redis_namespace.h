#pragma once

#include <sw/redis++/redis++.h>
#include <string_view>

namespace RedisLayer
{
    static sw::redis::Redis redis = sw::redis::Redis("tcp://1234@127.0.0.1");
}