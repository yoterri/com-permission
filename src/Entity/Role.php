<?php

namespace Com\Component\Permission\Entity;

use Com\Entity\AbstractEntity;
use Com\Interfaces\LazyLoadInterface;

class Role extends AbstractEntity implements LazyLoadInterface
{
	protected $properties = array(
        'id'
        ,'name'
        ,'description'
    );
}
