#include <mw/models/block/Block.h>

#include <mw/consensus/OwnerSumValidator.h>

void mw::Block::Validate() const
{
    m_body.Validate();

    OwnerSumValidator::Validate(m_pHeader->GetOwnerOffset(), m_body);
}