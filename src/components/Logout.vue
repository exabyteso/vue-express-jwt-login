<template>
    <button @click="logoutUser">Logout</button>
</template>

<script>
export default{
    methods: {
        logoutUser(e){
            if(localStorage.getItem('user') != null && localStorage.getItem('jwt') != null){
                localStorage.clear()
                this.$router.push('/login')
            }
        }
    }
}
</script>