package com.mis.parentapp.network

import com.mis.parentapp.BuildConfig
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.Header
import retrofit2.http.POST
import retrofit2.http.Path

interface FacultyChatApiService {
    @POST("api/auth/parent-login")
    suspend fun parentLogin(@Body request: ParentChatLoginRequest): ParentChatLoginResponse

    @GET("api/chat/history/{facultyId}")
    suspend fun getChatHistory(
        @Path("facultyId") facultyId: String,
        @Header("Authorization") authorization: String
    ): ChatHistoryResponse
}

object FacultyChatRetrofit {
    val BASE_URL = BuildConfig.FACULTY_CHAT_BASE_URL

    val api: FacultyChatApiService by lazy {
        Retrofit.Builder()
            .baseUrl(BASE_URL)
            .addConverterFactory(GsonConverterFactory.create())
            .build()
            .create(FacultyChatApiService::class.java)
    }
}
