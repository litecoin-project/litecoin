#include <mw/models/tx/Transaction.h>
#include <mw/consensus/KernelSumValidator.h>
#include <mw/consensus/OwnerSumValidator.h>

void mw::Transaction::Validate() const
{
    m_body.Validate();

    KernelSumValidator::ValidateForTx(*this);
    OwnerSumValidator::Validate(m_ownerOffset, m_body);
}