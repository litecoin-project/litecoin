#pragma once

#include <mw/node/CoinsView.h>

class StateValidator
{
public:
    StateValidator() = default;

    void Validate(const mw::ICoinsView& coins_view);
};