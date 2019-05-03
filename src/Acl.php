<?php

namespace Com\Component\Permission;

use Zend\Db\ResultSet\AbstractResultSet;
use Zend\Permissions\Acl\Acl as zendAcl;
use Zend\Db\Sql\Select;
use Zend\Db\Sql\Where;
use Zend\Db\Sql\Expression;

use Com\Interfaces\LazyLoadInterface;
use Com\Control\AbstractControl;

class Acl extends AbstractControl implements LazyLoadInterface
{

    /**
     * @var array
     */
    protected $hashTable;

    /**
     * @var zendAcl
     */
    protected $zendAcl;

    /**
     * @var string
     */
    protected $superAdminRoleName = null;

    /**
     * @var int
     */
    protected $userId = '';



    /**
     * @param int $userId
     * @return Control
     */
    function setUserId($userId)
    {
        $this->userId = (int)$userId;
        return $this;
    }

    /**
     * @return int
     */
    function getUserId()
    {
        return $this->userId;
    }



    /**
     * @param int $userId
     * @return bool
     */
    function isSuperAdmin($userId = null)
    {
        if(is_null($userId))
        {
            $userId = $this->getUserId();
        }
        
        $where = new Where();
        $where->equalTo('user_id', $userId)
            ->equalTo('role_id', 1);

        return 1 == $this->getContainer()
            ->get('Com\Component\Permission\Db\UserHasRole')
            ->count($where);
    }


    /**
     * Checks if the given user has any of the given capabililtes
     *
     * @param array $capabilities
     * @param int $userId
     * @return bool
     */
    function hasAnyCapability(array $capabilities, $userId = null)
    {
        foreach($capabilities as $capability)
        {
            $flag = $this->hasCapability($capability, $userId);
            if($flag)
            {
                return true;
            }
        }

        return false;
    }


    /**
     * Checks if the given user has all given capabililtes
     *
     * @param array $capabilities
     * @param int $userId
     * @return bool
     */
    function hasAllCapabilities(array $capabilities, $userId = null)
    {
        if(count($capabilities))
        {
            foreach($capabilities as $capability)
            {
                $flag = $this->hasCapability($capability, $userId);
                if(!$flag)
                {
                    return false;
                }

                return true;
            }
        }

        return false;
    }


    /**
     * @param string $capability
     * @param int $userId
     * @return bool
     */
    function hasCapability($capability, $userId = null)
    {
        if(is_null($userId))
        {
            $userId = $this->getUserId();
        }

        #
        $roles = $this->getUserRoles($userId);
        foreach($roles as $role)
        {
            if($this->roleHasCapability($role->name, $capability))
            {
                return true;
            }
        }

        return false;
    }


    /**
     * @param string $role
     * @param string $capability
     * @return bool
     */
    function roleHasCapability($role, $capability)
    {
        $role = strtolower($role);
        $capability = strtolower($capability);

        #
        if(isset($this->hashTable[$role]))
        {
            if(isset($this->hashTable[$role][$capability]))
            {
                return $this->hashTable[$role][$capability];
            }
        }




        #
        if(is_null($this->superAdminRoleName))
        {
            # the role where id=1 is the super admin
            # so we first need to get the name of the super admin role
            $sm = $this->getContainer();
            $dbRole = $sm->get('Com\Component\Permission\Db\Role');
            $row = $dbRole->findBy(['id' => 1])->current();
            if($row)
            {
                $this->superAdminRoleName = strtolower($row->name);
            }
        }

        #
        if($this->superAdminRoleName === $role)
        {
            $this->hashTable[$role][$capability] = true;
            return true;
        }
        

        #
        $zendAcl = $this->_getZendAcl();
        if(!$zendAcl->hasRole($role))
        {
            $this->hashTable[$role][$capability] = false;
            return false;
        }

        #
        $capability = strtolower($capability);
        if(!$zendAcl->hasResource($capability))
        {
            $this->hashTable[$role][$capability] = false;
            return false;
        }

        #
        $flag = $zendAcl->isAllowed($role, $capability);
        $this->hashTable[$role][$capability] = $flag;
        return $flag;
    }


    /**
     * @param string $role
     * @param int $userId
     * @return bool
     */
    function userHasRole($role, $userId = null)
    {
        if(is_null($userId))
        {
            $userId = $this->getUserId();
        }

        return $this->getContainer()
            ->get('Com\Component\Permission\Db\Role')
            ->userHasRole($userId, $role);
    }


    /**
     * @param int $userId
     * @return AbstractResultSet
     */
    function getUserRoles($userId = null)
    {
        if(is_null($userId))
        {
            $userId = $this->getUserId();
        }

        return $this->getContainer()
            ->get('Com\Component\Permission\Db\Role')
            ->findByUser($userId);
    }



    /**
     * @return zendAcl
     */
    protected function _getZendAcl()
    {
        if(!$this->zendAcl)
        {
            $sm = $this->getContainer();
            $this->zendAcl = new zendAcl();

            #
            $dbRole = $sm->get('Com\Component\Permission\Db\Role');
            $roles = $dbRole->findAll();
            foreach($roles as $role)
            {
                $this->zendAcl->addRole($role->name);
            }

            #
            $dbCap = $sm->get('Com\Component\Permission\Db\Capability');
            $capabilities = $dbCap->findAll();
            foreach($capabilities as $capability)
            {
                $this->zendAcl->addResource(strtolower($capability->name));
            }

            #
            $dbRoleCap = $sm->get('Com\Component\Permission\Db\RoleHasCapability');

            $select = new Select();
            $select->from(['rc' => $dbRoleCap]);
            $select->join(['r' => $dbRole], 'r.id = rc.role_id', []);
            $select->join(['c' => $dbCap], 'c.id = rc.capability_id', []);

            $select->columns([
                'role' => new Expression('r.name'),
                'capability' => new Expression('c.name'),
            ]);

            $entity = $sm->get('Com\Entity\Record');
            $rowset = $dbRoleCap->executeCustomSelect($select, $entity);
            foreach($rowset as $row)
            {
                if(!$this->zendAcl->hasRole($row->role))
                {
                    continue;
                }

                $capability = strtolower($row->capability);
                if(!$this->zendAcl->hasResource($capability))
                {
                    continue;
                }

                $this->zendAcl->allow($row->role, $capability);
            }
        }

        return $this->zendAcl;
    }
}
