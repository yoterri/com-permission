<?php

namespace Com\Component\Permission;

use Laminas\Db\ResultSet\AbstractResultSet;
use Laminas\Permissions\Acl\Acl as laminasAcl;
use Laminas\Db\Sql\Select;
use Laminas\Db\Sql\Where;
use Laminas\Db\Sql\Expression;

use Com\Interfaces\LazyLoadInterface;
use Com\Control\AbstractControl;

class Acl extends AbstractControl implements LazyLoadInterface
{

    /**
     * @var array
     */
    protected $hashTable;

    /**
     * @var laminasAcl
     */
    protected $laminasAcl;

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
        $laminasAcl = $this->_getLaminasAcl();
        if(!$laminasAcl->hasRole($role))
        {
            $this->hashTable[$role][$capability] = false;
            return false;
        }

        #
        $capability = strtolower($capability);
        if(!$laminasAcl->hasResource($capability))
        {
            $this->hashTable[$role][$capability] = false;
            return false;
        }

        #
        $flag = $laminasAcl->isAllowed($role, $capability);
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
     * @return laminasAcl
     */
    protected function _getLaminasAcl()
    {
        if(!$this->laminasAcl)
        {
            $sm = $this->getContainer();
            $this->laminasAcl = new laminasAcl();

            #
            $dbRole = $sm->get('Com\Component\Permission\Db\Role');
            $roles = $dbRole->findAll();
            foreach($roles as $role)
            {
                $this->laminasAcl->addRole($role->name);
            }

            #
            $dbCap = $sm->get('Com\Component\Permission\Db\Capability');
            $capabilities = $dbCap->findAll();
            foreach($capabilities as $capability)
            {
                $this->laminasAcl->addResource(strtolower($capability->name));
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
                if(!$this->laminasAcl->hasRole($row->role))
                {
                    continue;
                }

                $capability = strtolower($row->capability);
                if(!$this->laminasAcl->hasResource($capability))
                {
                    continue;
                }

                $this->laminasAcl->allow($row->role, $capability);
            }
        }

        return $this->laminasAcl;
    }
}
