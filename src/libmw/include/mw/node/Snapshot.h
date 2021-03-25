#pragma once

#include <mw/node/CoinsView.h>
#include <mw/node/State.h>

MW_NAMESPACE

class Snapshot
{
public:
    static State Build(const mw::ICoinsView::CPtr& pView);
};

END_NAMESPACE