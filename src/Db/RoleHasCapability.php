<?php

namespace Com\Component\Permission\Db;

use Com\Db\AbstractDb;
use Com\LazyLoadInterface;

class RoleHasCapability extends AbstractDb implements LazyLoadInterface
{
    protected $tableName = 'priv_role_has_capability';
    protected $entityClassName = 'Com\Component\Permission\Entity\RoleHasCapability';
}
