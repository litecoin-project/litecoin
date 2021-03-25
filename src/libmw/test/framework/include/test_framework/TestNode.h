#pragma once

#include <mw/node/INode.h>
#include <test_framework/DBWrapper.h>
#include <test_framework/TestUtil.h>

TEST_NAMESPACE

static mw::INode::Ptr CreateNode(const FilePath& datadir)
{
    return mw::InitializeNode(datadir, "unittest", nullptr, std::make_shared<TestDBWrapper>());
}

END_NAMESPACE