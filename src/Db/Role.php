<?php

namespace Com\Component\Permission\Db;

use Com\Db\AbstractDb;
use Com\Interfaces\LazyLoadInterface;

use Zend\Db\Sql\Select;
use Zend\Db\ResultSet\AbstractResultSet;

class Role extends AbstractDb implements LazyLoadInterface
{
    protected $tableName = 'priv_role';
    protected $entityClassName = 'Com\Component\Permission\Entity\Role';



    /**
     * @param string $name
     * @return Com\Entity\Priv\Role
     */
    function findByName($name)
    {
    	$where = $this->getWhere()
    		->equalTo('name', $name);

    	return $this->findBy($where)->current();
    }


    /**
     * @param string[] $names
     * @return AbstractResultSet
     */
    function findByNames(array $names)
    {
    	$where = $this->getWhere()
    		->in('name', $name);

    	return $this->findBy($where);
    }


    /**
     * @return AbstractResultSet
     */
    function findByUser($userId)
    {
    	$sm = $this->getContainer();

        #
        $dbUserRole = $sm->get('Com\Component\Permission\Db\UserHasRole');
        $dbRole = $this;

        $select = new Select();
        $select->from(['r' => $dbRole]);
        $select->join(['ur' => $dbUserRole], 'ur.role_id = r.id', []);

        $where = $this->getWhere()
            ->equalTo('ur.user_id', $userId);

        $select->where($where);

        #
        return $dbRole->executeCustomSelect($select);
    }


    /**
     * @param int $userId
     * @param string $role
     * @return bool
     */
    function userHasRole($userId, $role)
    {
    	$flag = false;

    	$roles = $this->findByUser($userId);
    	if($roles->count())
    	{
    		if($role)
            {
                $flag = $this->_hasRole($role, $roles);
            }
    	}

        return $flag;
    }


    protected function _hasRole($role, AbstractResultSet $roles)
    {
        $flag = false;

        $property = 'name';
        if(is_integer($role))
        {
            $property = 'id';
        }          

        foreach($roles as $row)
        {
            if(strtolower($row->$property) == strtolower($role))
            {
                $flag = true;
                break;
            }
        }

        return $flag;
    }

}
