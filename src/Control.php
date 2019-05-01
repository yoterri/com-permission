<?php

namespace Com\Component\Permission\Control;

use Com\LazyLoadInterface;
use Zend\Db\ResultSet\AbstractResultSet;

class Control extends AbstractControl implements LazyLoadInterface
{

	/**
     * @param int $userId
     * @return bool
     */
	function userIsSuperAdmin($userId)
	{
		$where = $this->getWhere()
            ->equalTo('user_id', $userId)
            ->equalTo('role_id', 1);

        return 1 == $this->getContainer()
            ->get('Com\Component\Permission\Db\UserHasRole')
            ->count($where);
	}


	/**
	 * @param int $userId
	 * @param string|string[] $capability
	 * @return bool
	 */
	function userHasCapability($userId, $capability)
	{
		$flag = false;

		$roles = $this->getUserRoles($userId);
		foreach($roles as $role)
		{
			if($this->roleHasCapability($role->id, $capability))
			{
				$flag = true;
				break;
			}
		}

		return $flag;
	}


	/**
     * @param string|int $role
     * @param string|string[] $capability
     * @return bool
     */
	function roleHasCapability($role, $capability)
	{
		return $this->getContainer()
			->get('Com\Component\Permission\Db\Capability')
			->roleHasCapability($role, $capability);
	}


	/**
     * @param int $userId
     * @param string|int|string[]|int[] $role
     * @return bool
     */
	function userHasRole($userId, $role)
	{
		return $this->getContainer()
			->get('Com\Component\Permission\Db\Role')
			->userHasRole($userId, $role);
	}


	/**
     * @return AbstractResultSet
     */
	function getUserRoles($userId)
	{
		return $this->getContainer()
			->get('Com\Component\Permission\Db\Role')
			->findByUser($userId);
	}
}
