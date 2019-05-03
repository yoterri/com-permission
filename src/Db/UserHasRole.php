<?php

namespace Com\Component\Permission\Db;

use Com\Db\AbstractDb;
use Com\Interfaces\LazyLoadInterface;

class UserHasRole extends AbstractDb implements LazyLoadInterface
{
    protected $tableName = 'priv_user_has_role';
    protected $entityClassName = 'Com\Component\Permission\Entity\UserHasRole';
}
