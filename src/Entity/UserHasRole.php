<?php

namespace Com\Component\Permission\Entity;

use Com\Entity\AbstractEntity;
use Com\Interfaces\LazyLoadInterface;

class UserHasRole extends AbstractEntity implements LazyLoadInterface
{
	protected $properties = array(
        'id'
        ,'user_id'
        ,'role_id'
    );
}
