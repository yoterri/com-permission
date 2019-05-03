<?php

namespace Com\Component\Permission\Entity;

use Com\Entity\AbstractEntity;
use Com\Interfaces\LazyLoadInterface;

class RoleHasCapability extends AbstractEntity implements LazyLoadInterface
{
	protected $properties = array(
        'id'
        ,'role_id'
        ,'capability_id'
    );
}
